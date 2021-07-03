from typing import Union, List
from io import BytesIO
import os
import json
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

    def execute_query(self, query_file: Union[str, os.PathLike, BytesIO] = None, query: dict = None):
        query_file_content = self.read_query_file(query_file)
        url = self._generate_url(query_file_content["query"])
        auth = self._generate_auth()
        query_results = self._get_query_results_from_api(url=url, auth=auth)

        result = self.parse_query_results(query_results)

        return result

    def _get_query_results_from_api(self, url: str, auth: HTTPBasicAuth) -> List[dict]:
        # TODO token based auth


        responses = []
        response = requests.get(url=url, auth=auth).json()
        responses.append(response)
        while True:
            ic("Getting next")

            next_page = next((link for link in response["link"] if link["relation"] == "next"), None)
            if not next_page:
                break
            response = requests.get(url=next_page["url"], auth=auth).json()
            responses.append(response)

        ic("Finished")
        return responses

    def parse_query_results(self, query_results):

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
    result = fhir_client.execute_query(query_file=query_json_path)
    # query_dict = fhir_client.execute_query(query_file=query_json_path)
