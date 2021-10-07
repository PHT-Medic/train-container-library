import json
import os
import uuid

import pytest
from train_lib.fhir import PHTFhirClient
from pathlib import Path
from dotenv import load_dotenv, find_dotenv
from io import BytesIO


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


@pytest.fixture
def minimal_query():
    return {
        "query": {
            "resource": "Patient",
            "parameters": [
                {
                    "variable": "gender",
                    "condition": "male"
                }
            ]
        },
        "data": {
            "output_format": "json",
            "filename": "patients.json",
            "variables": [
                "id",
                "birthDate",
                "gender"
            ]
        }
    }


def test_server_connection(pht_fhir_client: PHTFhirClient):
    pht_fhir_client.health_check()


def test_load_query_json(pht_fhir_client: PHTFhirClient, minimal_query):
    query_io = BytesIO(json.dumps(minimal_query).encode("utf-8"))
    query_dict = pht_fhir_client.read_query_file(query_io)

    assert isinstance(query_dict, dict)
