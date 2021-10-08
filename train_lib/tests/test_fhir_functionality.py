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


@pytest.fixture
def advanced_query():
    return {
        "query": {
            "resource": "Patient",
            "parameters": [
                {
                    "variable": "gender",
                    "condition": "male"
                },
                {
                    "variable": "birthdate",
                    "condition": "sa1980-08-12"
                }
            ],
            "has": [
                {
                    "resource": "Observation",
                    "property": "code",
                    "params": ["I63.0", "I63.1", "I63.2", "I63.3", "I63.4", "I63.5", "I63.6", "I63.7", "I63.8", "I63.9"]
                },
                {
                    "resource": "Condition",
                    "property": "code",
                    "params": ["D70.0", "D70.10", "D70.11", "D70.11", "D70.12", "D70.13", "D70.14", "D70.18", "D70.19",
                               "D70.3", "D70.5", "D70.6", "D70.7"]
                }
            ]
        },
        "data": {
            "output_format": "csv",
            "variables": [
                "id",
                "birthDate",
                "gender"
            ]
        }
    }


def test_server_connection(pht_fhir_client: PHTFhirClient):
    pht_fhir_client.health_check()


def test_load_query_json(pht_fhir_client: PHTFhirClient, minimal_query, advanced_query):
    query_io = BytesIO(json.dumps(minimal_query).encode("utf-8"))
    minimal_query_dict = pht_fhir_client.read_query_file(query_io)

    assert isinstance(minimal_query_dict, dict)

    query_io = BytesIO(json.dumps(advanced_query).encode("utf-8"))
    advanced_query_dict = pht_fhir_client.read_query_file(query_io)

    assert isinstance(advanced_query_dict, dict)





