from typing import Union, List
from io import BytesIO
import os
import json
import pandas as pd
from requests.auth import HTTPBasicAuth
import requests
from loguru import logger
import xmltodict

from .fhir_query_builder import build_query_string
from train_lib.clients.fhir import fhir_k_anonymity
from itertools import chain
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
import collections


class PHTFhirClient:
    def __init__(self, server_url: str = None, username: str = None, password: str = None, token: str = None,
                 client_id: str = None, client_secret: str = None, oidc_provider_url: str = None,
                 fhir_server_type: str = None, disable_auth: bool = False, k_anon: int = 5,
                 disable_k_anon: bool = False):
        """
        Fhir client for executing predefined queries contained in PHT trains. Supports IBM, Blaze, and HAPI FHIR servers

        :param server_url: base url of the FHIR server to execute the query against
        :param username: username for use in basic auth authentication against the fhir server
        :param password: password for use in basic auth
        :param token: token to use for authenticating against a FHIR server using a static bearer token
        :param client_id: client id for OIDC authentication flow
        :param client_secret: secret for OIDC authentication flow
        :param oidc_provider_url: url where a token can be obtained using client_id and client_secret
        :param fhir_server_type: the type of the server one of ["blaze", "hapi", "ibm"]
        """
        self.server_url = server_url if server_url else os.getenv("FHIR_SERVER_URL")
        if not self.server_url[-1] == "/":
            self.server_url = self.server_url + "/"
        self.username = username
        self.password = password
        self.token = token
        self.client_id = client_id
        self.client_secret = client_secret
        self.oidc_provider_url = oidc_provider_url

        self.fhir_server_type = fhir_server_type if fhir_server_type else os.getenv("FHIR_SERVER_TYPE")
        self.output_format = None
        self.disable_auth = disable_auth
        self.disable_k_anon = disable_k_anon
        self.k_anon = k_anon

        # Check for correct initialization based on env vars or constructor parameters
        if (self.username and self.password) and self.token:
            raise ValueError("Only one of username:pw or token auth can be selected")
        if not ((self.username and self.password) or self.token) and disable_auth:
            raise ValueError("Insufficient login information, either token or username and password need to be set.")
        if not self.server_url:
            raise ValueError("No FHIR server address given.")

    @classmethod
    def from_dict(cls, fhir_config: dict):
        # attempt to find the API address from the different options for environtment variables
        api_url = fhir_config.get("FHIR_SERVER_URL", os.get("FHIR_ADDRESS", os.get("FHIR_API_URL")))
        if not api_url:
            raise EnvironmentError("No FHIR Address could be found in the clients environment variables.")

        server_type = fhir_config.get("FHIR_SERVER_TYPE", "blaze")

        # attempt to load basic auth information
        username = fhir_config.get("FHIR_USER")
        if username:
            password = fhir_config.get("FHIR_PW")
            if not password:
                raise EnvironmentError("Username given but no password found in environment variables.")

            return cls(server_url=api_url, username=username, password=password, fhir_server_type=server_type)

        token = fhir_config.get("FHIR_TOKEN")
        if username and token:
            raise EnvironmentError("Conflicting auth information: both username and token are set.")

        if token:
            return cls(server_url=api_url, token=token, fhir_server_type=server_type)

        client_id = fhir_config.get("CLIENT_ID")
        client_secret = fhir_config.get("CLIENT_SECRET")
        oidc_provider = fhir_config.get("OIDC_PROVIDER_URL")

        if username and client_id:
            raise EnvironmentError("Conflicting auth information: both username and client id are set.")

        if token and client_id:
            raise EnvironmentError("Conflicting auth information: both token and client id are set.")

        if client_id:
            if not client_secret:
                raise EnvironmentError("No client secret set for oauth2 authentication flow.")
            if not oidc_provider:
                raise EnvironmentError("No provider URL given for oauth2 authentication flow.")

            return cls(server_url=api_url, client_id=client_id, client_secret=client_secret,
                       oidc_provider_url=oidc_provider, fhir_server_type=server_type)

        logger.info("No authentication info given, attempting access without it.")
        return cls(server_url=api_url, fhir_server_type=server_type, disable_auth=True)

    @classmethod
    def from_env(cls):
        """
        Initialize a client instance from environment variables.

        :return: an instance of the fhir client
        """

        # attempt to find the API address from the different options for environtment variables
        api_url = os.getenv("FHIR_SERVER_URL", os.getenv("FHIR_ADDRESS", os.getenv("FHIR_API_URL")))
        if not api_url:
            raise EnvironmentError("No FHIR Address could be found in the clients environment variables.")

        server_type = os.getenv("FHIR_SERVER_TYPE", "blaze")

        # attempt to load basic auth information
        username = os.getenv("FHIR_USER")
        if username:
            password = os.getenv("FHIR_PW")
            if not password:
                raise EnvironmentError("Username given but no password found in environment variables.")

            return cls(server_url=api_url, username=username, password=password, fhir_server_type=server_type)

        token = os.getenv("FHIR_TOKEN")
        if username and token:
            raise EnvironmentError("Conflicting auth information: both username and token are set.")

        if token:
            return cls(server_url=api_url, token=token, fhir_server_type=server_type)

        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        oidc_provider = os.getenv("OIDC_PROVIDER_URL")

        if username and client_id:
            raise EnvironmentError("Conflicting auth information: both username and client id are set.")

        if token and client_id:
            raise EnvironmentError("Conflicting auth information: both token and client id are set.")

        if client_id:
            if not client_secret:
                raise EnvironmentError("No client secret set for oauth2 authentication flow.")
            if not oidc_provider:
                raise EnvironmentError("No provider URL given for oauth2 authentication flow.")

            return cls(server_url=api_url, client_id=client_id, client_secret=client_secret,
                       oidc_provider_url=oidc_provider, fhir_server_type=server_type)

        logger.info("No authentication info given, attempting access without it.")
        return cls(server_url=api_url, fhir_server_type=server_type, disable_auth=True)

    def execute_query(self, query_file: Union[str, os.PathLike, BytesIO] = None,
                      query: dict = None, store_results: bool = False) -> pd.DataFrame:
        """
        Asynchronously build the query string and execute it against the given fhir server either based on a query.json
        file or based on a dictionary containing the query file content.
        :param query_file: definition of the query given in json format either a string, a path to a file or in memory
        file object
        :param query: dictionary containing query definition
        :param store_results: where to store the results to file
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

        if self.output_format == "xml":
            query_results = self._get_query_results_from_api_xml(url, auth)
        else:
            query_results = self._get_query_results_from_api_json(url=url, auth=auth,
                                                                  selected_variables=selected_variables)

        filename = query_file_content["data"]["filename"]

        if store_results:
            self.store_query_results(query_results, filename=filename)

        return query_results

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

        if self.output_format in ["raw", "json"]:
            with open(results_path, "w") as results_file:
                results_file.write(json.dumps(query_results, indent=2))

        # write xml string to file directly
        elif self.output_format == "xml":
            with open(results_path, "w") as results_file:
                results_file.write(query_results)

        else:
            raise ValueError(f"Unsupported output format: {self.output_format}")

        logger.info("Stored query results in {}", results_path)
        return results_path

    def _get_query_results_from_api_json(self, url: str, auth: requests.auth.AuthBase = None,
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

        r = requests.get(url, auth=auth)
        r.raise_for_status()

        initial_response = r.json()
        response = r.json()
        if (len(response["entry"]) < self.k_anon) and not self.disable_k_anon:
            raise ValueError("Too few results match the query. Response blocked by k-anonymity policy.")
        link = response.get("link", None)
        if not link:
            return response
        else:
            print("Resolving response pagination")
            entries = []
            entries.extend(response["entry"])

            while response.get("link", None):

                next_page = next((link for link in response["link"] if link.get("relation", None) == "next"), None)
                if next_page:
                    response = requests.get(next_page["url"], auth=auth).json()
                    entries.extend(response["entry"])
                else:
                    break

            initial_response["entry"] = entries
            return initial_response

    def _get_query_results_from_api_xml(self, url: str, auth: requests.auth.AuthBase = None) -> str:
        server_response = requests.get(url, auth=auth)
        initial_response = xmltodict.parse(server_response.text)
        entries = initial_response["Bundle"]["entry"]
        response = initial_response
        while True:
            next_page = False
            for link in response["Bundle"]["link"]:
                if isinstance(link, collections.OrderedDict):
                    relation_dict = dict(link["relation"])
                else:
                    break
                if relation_dict.get("@value") == "next":
                    print("Getting next")
                    # get url and extend with xml format
                    url = link["url"]["@value"]
                    url = url + "&_format=xml"
                    r = requests.get(url, auth=auth)
                    r.raise_for_status()
                    response = xmltodict.parse(r.text)
                    added_entries = response["Bundle"]["entry"]
                    entries.extend(added_entries)
                    # Stop resolving the pagination when the limit is reached
                    next_page = True

            if not next_page:
                print("All pages found")
                break
        # added the paginated resources to the initial response
        initial_response["Bundle"]["entry"] = entries

        if (len(entries) < self.k_anon) and not self.disable_k_anon:
            raise ValueError("Too few results match the query. Response blocked by k-anonymity policy.")
        full_response_xml = xmltodict.unparse(initial_response, pretty=True)
        return full_response_xml

    def health_check(self):

        api_url = self.server_url + "metadata"
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
        if isinstance(file, BytesIO):
            query_file = file.read()
        else:
            with open(file, "r") as f:
                query_file = f.read()
        query_file = json.loads(query_file)
        return query_file

    def _generate_url(self, query: Union[dict, list, str], limit=5000):
        """
        Generates the fhir search url to request from the server based. Either based on a previously given query string
        or based on a dictionary containing the query definition in the query.json file.

        :param query: dictionary containing the content of the query definition in the query.json file
        :param query_string: Predefined Fhir url query string to append to base server url
        :param return_format: the format in which the server should return the data.
        :param limit: the max number of entries in a paginated response
        :return: url string to perform a request against a fhir server with
        """

        if self.server_url[-1] == "/":
            url = self.server_url
        else:
            url = self.server_url + "/"

        if isinstance(query, dict):
            url += build_query_string(query_dict=query)
        elif isinstance(query, list):
            url += build_query_string(query_dict=query)
        elif isinstance(query, str):
            url += query
        else:
            raise ValueError("Either query dictionary or string need to be given")

        # add formatting configuration

        if url[-1] == "?":
            url += f"_format={self.output_format}&_count={limit}"
        else:
            url += f"&_format={self.output_format}&_count={limit}"

        return url

    def _generate_auth(self) -> requests.auth.AuthBase:
        """
        Generate authentication for the request to be sent to server. Based on a given bearer token, basic
        auth with username and password or by requesting a new token using oauth2.

        :return: Auth object to pass to a requests call.
        """
        if self.username and self.password:
            logger.info("Using basic auth")
            return HTTPBasicAuth(username=self.username, password=self.password)
        # TODO request token from id provider if configured
        elif self.token:
            logger.info("Using static token auth.")
            return BearerAuth(token=self.token)

        elif self.client_id and self.client_secret and self.oidc_provider_url:
            logger.info("Requesting oauth2 token")
            client = BackendApplicationClient(client_id=self.client_id)
            oauth = OAuth2Session(client=client)
            token = oauth.fetch_token(
                token_url=self.oidc_provider_url,
                client_secret=self.client_secret,
                client_id=self.client_id
            )
            self.token = token["access_token"]
            return BearerAuth(token=self.token)


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r
