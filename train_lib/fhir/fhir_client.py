from typing import Union, List
from io import BytesIO
import os
import json
import pandas as pd
from requests.auth import HTTPBasicAuth
import requests
from dotenv import load_dotenv, find_dotenv
from icecream import ic
import httpx
import asyncio
from fhir.resources.patient import Patient
from fhir.resources.media import Media

import fhir_k_anonymity


class PHTFhirClient:
    def __init__(self, server_url: str = None, username: str = None, password: str = None, token: str = None,
                 server_type: str = "ibm"):
        self.server_url = server_url if server_url else os.getenv("FHIR_SERVER_URL")
        self.username = username if username else os.getenv("FHIR_USER")
        self.password = password if password else os.getenv("FHIR_PW")
        self.token = token if token else os.getenv("FHIR_TOKEN")
        self.server_type = server_type

        if not (self.username and self.password) or self.token:
            raise ValueError("Insufficient login information, either token or username and password need to be set.")

        if not self.server_url:
            raise ValueError("No FHIR server address available")

    async def execute_query(self, query_file: Union[str, os.PathLike, BytesIO] = None, query: dict = None):

        if query and query_file:
            raise ValueError("Only specify one of query file or query")

        if query:
            query_file_content = query
        else:
            query_file_content = self.read_query_file(query_file)
        # Generate url query string and generate auth (basic)
        url = self._generate_url(query_file_content["query"])
        auth = self._generate_auth()
        selected_variables = query_file_content["data"].get("variables", None)

        query_results = await self._get_query_results_from_api(url=url, auth=auth,
                                                               selected_variables=selected_variables)

        # result = self.parse_query_results(query_results, selected_variables=selected_variables)

        output_format = query_file_content["data"]["output_format"]
        if output_format == "csv":
            query_results.to_csv("query_results.csv", index=False)
        # TODO add more output formats

        return query_results

    async def _get_query_results_from_api(self, url: str, auth: HTTPBasicAuth,
                                          selected_variables: List[str] = None, k_anonymity: int = 5) -> pd.DataFrame:
        dfs = []

        async with httpx.AsyncClient() as client:
            ic(url)
            task = asyncio.create_task(client.get(url=url, auth=auth))
            response = await task
            response = response.json()
            #  Process all the pages contained in the response
            while True:
                # TODO improve this
                if response.get("link", None):
                    next_page = next((link for link in response["link"] if link["relation"] == "next"), None)
                else:
                    break
                if next_page:
                    ic("Getting next page")
                    # Schedule a new task for new page
                    task = asyncio.create_task(client.get(url=next_page["url"], auth=auth))
                    # Process the previous response
                    df = self._process_fhir_response(response, selected_variables=selected_variables)
                    if df:
                        dfs.append(df)
                    response = await task
                    response = response.json()

                else:
                    df = self._process_fhir_response(response, selected_variables=selected_variables)
                    if df:
                        dfs.append(df)
                    break

        ic("Finished")
        if dfs:
            result = pd.concat(dfs)
        else:
            raise ValueError("No Results matched the given query.")
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

    @staticmethod
    def _process_fhir_response(response: dict, selected_variables: List[str] = None):

        entries = []

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

    @staticmethod
    def parse_query_results(query_results: List[dict], selected_variables: List[str] = None):

        entries = []
        for page in query_results:
            for entry in page["entry"]:
                series_entry = pd.Series(entry["resource"])[selected_variables]
                entries.append(series_entry)

        full_df = pd.concat(entries, axis=1)
        full_df = full_df.T
        print(full_df.info())
        return full_df

    @staticmethod
    def read_query_file(file: Union[str, os.PathLike, BytesIO]) -> dict:
        if type(file) == BytesIO:
            query_file = file.read()
        else:
            with open(file, "r") as f:
                query_file = f.read()
        query_file = json.loads(query_file)
        return query_file

    def _generate_url(self, query: dict, return_format="json", limit=1000):
        url = self.server_url
        if self.server_type == "ibm":
            url += "/fhir-server/api/v4/"

        elif self.server_type in ["blaze", "hapi"]:
            url += "/fhir/"

        url += query["resource"] + "?"

        # if there are query parameters given append them after the resource
        if query.get("parameters", None):
            for parameter in query["parameters"]:
                url += f"{parameter['variable']}={parameter['condition']}"

            # add format parameters
            url = url + f"&_format=[{return_format}]&_count={limit}"
        # Only add format parameters
        else:
            url = url + f"_format=[{return_format}]&_count={limit}"

        return url

    def _generate_auth(self) -> requests.auth.AuthBase:
        if self.username and self.password:
            return HTTPBasicAuth(username=self.username, password=self.password)
        elif self.token:
            return BearerAuth(token=self.token)

        # TODO request token from id provider if configured


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


if __name__ == '__main__':
    query_json_path = "query.json"
    load_dotenv(find_dotenv())
    print("Server", os.getenv("FHIR_SERVER_URL"))
    fhir_client = PHTFhirClient()
    loop = asyncio.get_event_loop()

    result = loop.run_until_complete(fhir_client.execute_query(query_file=query_json_path))

    print(fhir_k_anonymity.is_k_anonymized(result))
    ic(result)
    # query_dict = fhir_client.execute_query(query_file=query_json_path)
