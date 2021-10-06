import json
import os
import uuid

import pytest
from train_lib.fhir import PHTFhirClient
from pathlib import Path
from dotenv import load_dotenv, find_dotenv


@pytest.fixture
def pht_fhir_client():
    load_dotenv(find_dotenv())
    client = PHTFhirClient(
        server_url=os.getenv("FHIR_SERVER_URL"),
        username=os.getenv("FHIR_USER"),
        password=os.getenv("FHIR_PW"),
        fhir_server_type=os.getenv("FHIR_SERVER_TYPE"),
        disable_k_anon=True
    )
    return client


def test_server_connection(pht_fhir_client: PHTFhirClient):
    pht_fhir_client.health_check()


def test_load_query_json(pht_fhir_client: PHTFhirClient):
    path = Path(__file__).resolve().parent.joinpath("fhir").joinpath("query.json")

    with open(path, "r") as f:
        q_dict = json.load(f)
    print(q_dict)
    query_dict = pht_fhir_client.read_query_file(path)
