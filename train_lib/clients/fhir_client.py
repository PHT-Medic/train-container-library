from typing import Union, List
from io import BytesIO
import os
import json

import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv, find_dotenv
from icecream import ic
import httpx
import asyncio


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
            raise ValueError("Only specifiy one of query file or query")

        if query:
            query_file_content = query
        else:
            query_file_content = self.read_query_file(query_file)
        # Generate url query string and generate auth (basic)
        url = self._generate_url(query_file_content["query"])
        auth = self._generate_auth()
        selected_variables = query_file_content["data"]["variables"]

        query_results = await self._get_query_results_from_api(url=url, auth=auth,
                                                               selected_variables=selected_variables)

        # result = self.parse_query_results(query_results, selected_variables=selected_variables)

        # TODO store results in selected format

        return query_results

    async def _get_query_results_from_api(self, url: str, auth: HTTPBasicAuth,
                                          selected_variables: List[str] = None, k_anonimity: int = 5) -> pd.DataFrame:
        # TODO token based auth

        # responses = []
        dfs = []

        async with httpx.AsyncClient() as client:
            task = asyncio.create_task(client.get(url=url, auth=auth))
            response = await task
            response = response.json()
            # responses.append(response)

            # Assert that the response contains at least 5 entries

            assert len(response["entry"]) >= k_anonimity

            while True:
                ic("Getting next page")
                next_page = next((link for link in response["link"] if link["relation"] == "next"), None)
                if next_page:
                    # Schedule a new task for new page
                    task = asyncio.create_task(client.get(url=next_page["url"], auth=auth))
                    # Process the previous response
                    df = self._process_fhir_response(response, selected_variables=selected_variables)
                    dfs.append(df)
                    response = await task
                    response = response.json()
                    # responses.append(response)

                else:
                    df = self._process_fhir_response(response, selected_variables=selected_variables)
                    dfs.append(df)
                    break

        ic("Finished")
        result = pd.concat(dfs)
        return result

    def _process_fhir_response(self, response: dict, selected_variables: List[str] = None):

        entries = []
        if selected_variables:
            for entry in response["entry"]:
                series_entry = pd.Series(entry["resource"])[selected_variables]
                entries.append(series_entry)

            df = pd.concat(entries, axis=1)
            df = df.T

            return df
        return response["entry"]

    def parse_query_results(self, query_results: List[dict], selected_variables: List[str] = None):

        entries = []
        for page in query_results:
            for entry in page["entry"]:
                series_entry = pd.Series(entry["resource"])[selected_variables]
                entries.append(series_entry)

        full_df = pd.concat(entries, axis=1)
        full_df = full_df.T
        print(full_df.info())
        return full_df

    def _parse_entries(self, entries: List[dict]):
        pass

    def read_query_file(self, file: Union[str, os.PathLike, BytesIO]) -> dict:
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

        url += query["resource"] + "?"

        for parameter in query["parameters"]:
            url += f"{parameter['variable']}={parameter['condition']}"

        url = url + f"&_format=[{return_format}]&_count={limit}"

        return url

    def _generate_auth(self) -> HTTPBasicAuth:
        if self.username and self.password:
            return HTTPBasicAuth(username=self.username, password=self.password)
        else:
            # TODO token based auth
            pass


if __name__ == '__main__':
    query_json_path = "../fhir/query.json"
    load_dotenv(find_dotenv())
    print("Server", os.getenv("FHIR_SERVER_URL"))
    fhir_client = PHTFhirClient()
    loop = asyncio.get_event_loop()

    result = loop.run_until_complete(fhir_client.execute_query(query_file=query_json_path))
    ic(result)
    # query_dict = fhir_client.execute_query(query_file=query_json_path)
