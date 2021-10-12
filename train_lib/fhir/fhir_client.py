from typing import Union, List
from io import BytesIO
import os
import json
import pandas as pd
from requests.auth import HTTPBasicAuth
import requests
import httpx
import asyncio
from fhir.resources.bundle import Bundle
from loguru import logger

from train_lib.fhir.fhir_query_builder import build_query_string
from train_lib.fhir import fhir_k_anonymity
from itertools import chain


class PHTFhirClient:
    def __init__(self, server_url: str = None, username: str = None, password: str = None, token: str = None,
                 fhir_server_type: str = None, disable_auth: bool = False, disable_k_anon: bool = False):
        """
        Fhir client for executing predefined queries contained in PHT trains. Supports IBM, Blaze, and HAPI FHIR servers

        :param server_url: base url of the FHIR server to execute the query against
        :param username: username for use in basic auth authentication against the fhir server
        :param password: password for use in basic auth
        :param token: token to use for authenticating against a FHIR server using a bearer token
        :param fhir_server_type: the type of the server one of ["blaze", "hapi", "ibm"]
        """
        self.server_url = server_url if server_url else os.getenv("FHIR_SERVER_URL")
        self.username = username if username else os.getenv("FHIR_USER")
        self.password = password if password else os.getenv("FHIR_PW")
        self.token = token if token else os.getenv("FHIR_TOKEN")
        self.fhir_server_type = fhir_server_type if fhir_server_type else os.getenv("FHIR_SERVER_TYPE")
        self.output_format = None
        self.disable_auth = disable_auth
        self.disable_k_anon = disable_k_anon

        # Check for correct initialization based on env vars or constructor parameters
        if (self.username and self.password) and self.token:
            raise ValueError("Only one of username:pw or token auth can be selected")
        if not ((self.username and self.password) or self.token) and disable_auth:
            raise ValueError("Insufficient login information, either token or username and password need to be set.")
        if not self.server_url:
            raise ValueError("No FHIR server address given.")

    async def execute_query(self, query_file: Union[str, os.PathLike, BytesIO] = None,
                            query: dict = None, store_results: bool = False) -> pd.DataFrame:
        """
        Asynchronously build the query string and execute it against the given fhir server either based on a query.json
        file or based on a dictionary containing the query file content.
        :param query_file: definition of the query given in json format either a string, a path to a file or in memory
        file object
        :param query: dictionary containing query definition
        :return:
        """
        if query and query_file:
            raise ValueError("Only specify one of query file or query dictionary")
        if query and isinstance(query, dict):
            query_file_content = query
        else:
            query_file_content = self.read_query_file(query_file)

        # set the output format
        self.output_format = query_file_content["data"]["output_format"]
        # Generate url query string and generate auth (basic)
        url = self._generate_url(query_file_content["query"])
        auth = self._generate_auth()
        selected_variables = query_file_content["data"].get("variables", None)
        #
        # query_results = await self._get_query_results_from_api(url=url, auth=auth,
        #                                                        selected_variables=selected_variables)

        query_results = self._get_query_results_from_api_sync(url=url, auth=auth,
                                                              selected_variables=selected_variables)

        filename = query_file_content["data"]["filename"]
        if store_results:
            self.store_query_results(query_results, filename=filename)

        return query_results

    async def _get_query_results_from_api(self, url: str, auth: requests.auth.AuthBase = None,
                                          selected_variables: List[str] = None, k_anonymity: int = 5) -> pd.DataFrame:
        """
        Executes the query against the server based on the create FHIR search URL query.
        Checks if the results conform to the k-anonymity settings and attempts to generalize to make them k-anon
        conform.

        :param url: the full url to query, containing the fhir search definition based on the query file
        :param auth: auth that will be supplied to request performed against the server. Can either be basic auth or
        bearer token based authentication
        :param selected_variables: the variables that will be parsed from the results
        :param k_anonymity: k parameter for k-anonymity, that the results will be validated against
        :return: Dataframe containing the selected variables
        """
        data = []

        async with httpx.AsyncClient() as client:
            logger.info("Querying server with url: {}", url)
            task = asyncio.create_task(client.get(url=url, auth=auth))
            response = await task
            response = response.json()
            # Basic k-anon -> check if there are more than k responses in the returned results. if not throw an error
            if len(response["entry"]) < k_anonymity:
                raise ValueError(
                    f"Number of total responses n={len(response['entry'])} is too low, for basic k-anonymity.")
            #  Process all the pages contained in the response
            while True:
                # todo improve this
                if response.get("link", None):
                    next_page = next((link for link in response["link"] if link.get("relation", None) == "next"), None)
                else:
                    break
                if next_page:
                    logger.info("Getting next page in paginated FHIR response.")
                    # Schedule a new task for new page
                    task = asyncio.create_task(client.get(url=next_page["url"], auth=self._generate_auth()))
                    # Process the previous response
                    response_data = self._process_fhir_response(response, selected_variables=selected_variables)
                    if response_data is not None:
                        data.append(response_data)
                    response = await task
                    response = response.json()

                else:
                    response_data = self._process_fhir_response(response, selected_variables=selected_variables)
                    if response_data is None:
                        pass
                    else:
                        data.append(response_data)
                    break

        if data:
            logger.info("Aggregating FHIR response")
            if self.output_format == "csv":
                result = pd.concat(data)
            else:
                result = list(chain.from_iterable(data))

        else:
            raise ValueError("No Results matched the given query.")

        # it's not possible to check raw output for k-anonymity so only check parsed responses
        if self.output_format == "csv":

            logger.info("Checking if the response satisfies k-anonymity with k = {}...", k_anonymity)
            # Check if the returned results satisfy k-anonymity
            if fhir_k_anonymity.is_k_anonymized(result, k=k_anonymity):
                return result
            # Attempt to generalize the dataframe
            else:
                anon_df = fhir_k_anonymity.anonymize(result, k=k_anonymity)
                if anon_df:
                    return anon_df
                else:
                    raise PermissionError(
                        f"Query results did not satisfy the desired k-anonymity properties of k = {k_anonymity}")
        else:
            logger.info("Returning unvalidated results.")
            return result

    def _get_query_results_from_api_sync(self, url: str, auth: requests.auth.AuthBase = None,
                                         selected_variables: List[str] = None, k_anonymity: int = 5):
        """
        Blocking version of the querying a fhir server with the given search url. Processes all next relations in the
        response to get the full response in a single file.

        :param url:
        :param auth:
        :param selected_variables:
        :param k_anonymity:
        :return:
        """

        data = []
        logger.info("Querying server with url: {}", url)

        r = requests.get(url, auth=auth)
        r.raise_for_status()
        response = r.json()

        # Basic k-anon -> check if there are more than k responses in the returned results. if not throw an error
        if response["total"] < k_anonymity:
            raise ValueError(f"Number of total responses n={response['total']} is too low, for basic k-anonymity.")

        data.extend(self._process_fhir_response(response, selected_variables=selected_variables))

        while True:
            if response.get("link", None):
                next_page = next((link for link in response["link"] if link.get("relation", None) == "next"), None)
            else:
                break

            if next_page:
                logger.info("Getting next page in paginated FHIR response.")

                r = requests.get(url=next_page["url"], auth=self._generate_auth())
                r.raise_for_status()
                response = r.json()
                data.extend(self._process_fhir_response(response, selected_variables=selected_variables))

            else:
                break

        if data:
            logger.info("Aggregating FHIR response")
            if self.output_format == "csv":
                result = pd.concat(data)
            else:
                result = list(chain.from_iterable(data))

        else:
            raise ValueError("No Results matched the given query.")

        # it's not possible to check raw output for k-anonymity so only check parsed responses
        if self.output_format == "csv" and not self.disable_k_anon:

            logger.info("Checking if the response satisfies k-anonymity with k = {}...", k_anonymity)
            # Check if the returned results satisfy k-anonymity
            if fhir_k_anonymity.is_k_anonymized(result, k=k_anonymity):
                return result
            # Attempt to generalize the dataframe
            else:
                anon_df = fhir_k_anonymity.anonymize(result, k=k_anonymity)
                if anon_df:
                    return anon_df
                else:
                    raise PermissionError(
                        f"Query results did not satisfy the desired k-anonymity properties of k = {k_anonymity}")
        else:
            logger.info("Returning unvalidated results.")
            return result

    def store_query_results(self, query_results, filename: str, storage_dir: str = None) -> str:
        """
        Store the results from the query according to the output format specified in the query file

        :param query_results: The parsed or raw response from a fhir server to the given query
        :param filename: name for the results file (defined in query.json)
        :param storage_dir: directory in which the data should be stored
        :return:
        """

        storage_dir = storage_dir if storage_dir else os.getenv("TRAIN_DATA_DIR")
        if not storage_dir:
            logger.warning("No storage directory specified, saving results to current working directory.")
            results_path = filename
        else:
            results_path = os.path.join(storage_dir, filename)

        if self.output_format == "csv":
            if not isinstance(query_results, pd.DataFrame):
                raise ValueError(
                    f"Only FHIR responses parsed into a dataframe can be serialized to csv."
                    f" Results are {type(query_results)}")
            else:
                query_results.to_csv(results_path)

        elif self.output_format in ["raw", "json"]:
            with open(results_path, "w") as results_file:
                results_file.write(json.dumps(query_results, indent=2))

        else:
            raise ValueError(f"Unsupported output format: {self.output_format}")

        logger.info("Stored query results in {}", results_path)
        return results_path

    def upload_resource_or_bundle(self, resource=None, bundle: Bundle = None):
        """
        Upload a fhir resources bundle or single resource in json format to the FHIR client associated with this
        instance
        :param resource: FHIR resource in json format
        :param bundle: FHIR Bundle containing multiple resources grouped in a transaction
        :return:
        """

        auth = self._generate_auth()
        api_url = self._generate_api_url()
        if bundle:
            self._upload_bundle(bundle=bundle, api_url=api_url, auth=auth)
        if resource:
            # TODO upload single resource
            pass

    def _upload_bundle(self, bundle: Bundle, api_url: str, auth: requests.auth.AuthBase):
        headers = self._generate_bundle_headers()
        r = requests.post(api_url, auth=auth, data=bundle.json(), headers=headers)
        r.raise_for_status()

    def _generate_bundle_headers(self):
        headers = {}
        if self.fhir_server_type == "blaze":
            headers["Content-Type"] = "application/fhir+json"

        else:
            headers["Content-Type"] = "application/fhir+json"

        return headers

    def health_check(self):

        api_url = self._generate_api_url() + "/metadata"
        auth = self._generate_auth()

        r = requests.get(api_url, auth=auth)
        r.raise_for_status()

    def _process_fhir_response(self, response: dict, selected_variables: List[str] = None) -> \
            Union[pd.DataFrame, List[dict], None]:
        """
        Parses the fhir response into a dataframe. If selected variables are given only these are parsed from the
        response and returned

        :param response: the response data to the query from a fhir server
        :param selected_variables: list variable names to parse from the response
        :return:
        """
        entries = []

        if self.output_format == "df":
            if response.get("entry", None):
                for entry in response["entry"]:
                    if selected_variables:
                        series_entry = pd.Series(entry["resource"])[selected_variables]
                    else:
                        series_entry = pd.Series(entry["resource"])
                    entries.append(series_entry)

                df = pd.concat(entries, axis=1)
                df = df.T

                return df
            else:
                return None

        else:
            return response["entry"]

    @staticmethod
    def read_query_file(file: Union[str, os.PathLike, BytesIO]) -> dict:
        """
        Reads the content of a query.json file either given as a path or as in memory file object
        :param file: path to file or in memory file object to parse
        :return: dictionary representation of the query.json file
        """
        if type(file) == BytesIO:
            query_file = file.read()
        else:
            with open(file, "r") as f:
                query_file = f.read()
        query_file = json.loads(query_file)
        return query_file

    def _generate_url(self, query: Union[dict, list, str], return_format="json", limit=1000):
        """
        Generates the fhir search url to request from the server based. Either based on a previously given query string
        or based on a dictionary containing the query definition in the query.json file.

        :param query: dictionary containing the content of the query definition in the query.json file
        :param query_string: Predefined Fhir url query string to append to base server url
        :param return_format: the format in which the server should return the data.
        :param limit: the max number of entries in a paginated response
        :return: url string to perform a request against a fhir server with
        """
        url = self._generate_api_url() + "/"
        if isinstance(query, dict):
            url += build_query_string(query_dict=query)
        elif isinstance(query, list):
            url += build_query_string(query_dict=query)
        elif isinstance(query, str):
            url += query
        else:
            raise ValueError("Either query dictionary or string need to be given")
        # add formatting configuration
        url += f"&_format={return_format}&_count={limit}"

        return url

    def _generate_api_url(self) -> str:
        url = self.server_url
        if self.fhir_server_type == "ibm":
            url += "/fhir-server/api/v4"

        elif self.fhir_server_type in ["blaze", "hapi"]:
            url += "/fhir"

        else:
            raise ValueError(f"Unsupported FHIR server type: {self.fhir_server_type}")

        return url

    def _generate_auth(self) -> requests.auth.AuthBase:
        """
        Generate authoriation for the request to be sent to server. Either based on a given bearer token or using basic
        auth with username and password.

        :return: Auth object to pass to a requests call.
        """
        if self.username and self.password:
            return HTTPBasicAuth(username=self.username, password=self.password)
        # TODO request token from id provider if configured
        elif self.token:
            return BearerAuth(token=self.token)


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r
