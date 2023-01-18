import json
import os
from io import BytesIO
from unittest import mock

import pytest
from dotenv import find_dotenv, load_dotenv

from train_lib.clients import PHTFhirClient
from train_lib.clients.fhir import build_query_string, load_query_file


@pytest.fixture
def pht_fhir_client():
    load_dotenv(find_dotenv())
    client = PHTFhirClient(
        server_url=os.getenv("FHIR_SERVER_URL"),
        username=os.getenv("FHIR_USER"),
        password=os.getenv("FHIR_PW"),
        fhir_server_type=os.getenv("FHIR_SERVER_TYPE"),
        disable_k_anon=True,
    )
    return client


@pytest.fixture
def minimal_query():
    return {
        "query": {
            "resource": "Patient",
            "parameters": [{"variable": "gender", "condition": "male"}],
        },
        "data": {
            "output_format": "json",
            "filename": "patients.json",
        },
    }


@pytest.fixture
def advanced_query():
    return {
        "query": {
            "resource": "Patient",
            "parameters": [
                {"variable": "gender", "condition": ["male", "female"]},
                {"variable": "birthdate", "condition": "gt1980-08-12"},
            ],
            "has": [
                {
                    "resource": "Observation",
                    "property": "code",
                    "params": [
                        "I63.0",
                        "I63.1",
                        "I63.2",
                        "I63.3",
                        "I63.4",
                        "I63.5",
                        "I63.6",
                        "I63.7",
                        "I63.8",
                        "I63.9",
                    ],
                },
                {"resource": "Condition", "property": "code", "params": "D70.0"},
            ],
        },
        "data": {"output_format": "json", "filename": "patients.json"},
    }


def test_client_from_env():
    user = "test_user"
    password = "test_password"
    token = "test_token"
    client_id = "test_client_id"
    client_secret = "test_client_secret"
    oidc_url = "test_oidc_url"

    with mock.patch.dict(
        os.environ,
        {
            "FHIR_SERVER_URL": "test_address",
            "FHIR_USER": user,
            "FHIR_PW": password,
            "FHIR_TOKEN": "",
        },
    ):
        client = PHTFhirClient.from_env()

        assert client.username == user
        assert client.password == password

    with mock.patch.dict(
        os.environ,
        {
            "FHIR_SERVER_URL": "test_address",
            "FHIR_USER": user,
            "FHIR_PW": "",
            "FHIR_TOKEN": "",
        },
    ):
        with pytest.raises(EnvironmentError):
            client = PHTFhirClient.from_env()

    with mock.patch.dict(
        os.environ,
        {
            "FHIR_SERVER_URL": "test_address",
            "FHIR_USER": "",
            "FHIR_PW": "",
            "FHIR_TOKEN": token,
        },
    ):
        client = PHTFhirClient.from_env()
        assert client.token == token

    with mock.patch.dict(
        os.environ,
        {
            "FHIR_SERVER_URL": "test_address",
            "FHIR_USER": user,
            "FHIR_PW": "",
            "FHIR_TOKEN": token,
        },
    ):
        with pytest.raises(EnvironmentError):
            client = PHTFhirClient.from_env()

    with mock.patch.dict(
        os.environ,
        {
            "FHIR_SERVER_URL": "test_address",
            "FHIR_USER": "",
            "FHIR_PW": "",
            "FHIR_TOKEN": "",
            "CLIENT_ID": client_id,
            "CLIENT_SECRET": client_secret,
            "OIDC_PROVIDER_URL": oidc_url,
        },
    ):
        client = PHTFhirClient.from_env()

        assert client.client_id == client_id

    with mock.patch.dict(
        os.environ,
        {
            "FHIR_SERVER_URL": "test_address",
            "FHIR_USER": "",
            "FHIR_PW": "",
            "FHIR_TOKEN": "",
            "CLIENT_ID": client_id,
            "CLIENT_SECRET": "",
            "OIDC_PROVIDER_URL": oidc_url,
        },
    ):
        with pytest.raises(EnvironmentError):
            client = PHTFhirClient.from_env()

    with mock.patch.dict(
        os.environ,
        {
            "FHIR_SERVER_URL": "test_address",
            "FHIR_USER": "hello",
            "FHIR_PW": "",
            "FHIR_TOKEN": "",
            "CLIENT_ID": client_id,
            "CLIENT_SECRET": client_secret,
            "OIDC_PROVIDER_URL": oidc_url,
        },
    ):
        with pytest.raises(EnvironmentError):
            client = PHTFhirClient.from_env()


def test_query_marius(pht_fhir_client: PHTFhirClient):
    query = {
        "query": {
            "resource": "Patient",
            "parameters": [
                {"variable": "gender", "condition": "male"},
                {"variable": "birthdate", "condition": "sa1980-08-12"},
            ],
            "has": [
                {
                    "resource": "Condition",
                    "property": "code",
                    "params": [
                        "E70.0",
                        "E70.1",
                        "E84.0",
                        "E84.1",
                        "E84.8",
                        "E84.80",
                        "E84.87",
                        "E84.88",
                        "E84.9",
                    ],
                }
            ],
        },
        "data": {"output_format": "xml", "filename": "patients.xml"},
    }

    query2 = {
        "query": {
            "resource": "Patient",
            "parameters": [{"variable": "birthdate", "condition": "gt1960-08-12"}],
            "has": [{"resource": "Condition", "property": "code", "params": ["E70.0"]}],
        },
        "data": {"output_format": "xml", "filename": "patients.xml"},
    }
    query_string = build_query_string(query["query"])
    print(query_string)
    query_string = build_query_string(query2["query"])
    print(query_string)


def test_server_connection(pht_fhir_client: PHTFhirClient):
    pht_fhir_client.health_check()


def test_load_query_json(pht_fhir_client: PHTFhirClient, minimal_query, advanced_query):
    query_io = BytesIO(json.dumps(minimal_query).encode("utf-8"))
    minimal_query_dict = pht_fhir_client.read_query_file(query_io)

    assert isinstance(minimal_query_dict, dict)
    assert minimal_query == minimal_query_dict

    query_io = BytesIO(json.dumps(advanced_query).encode("utf-8"))
    advanced_query_dict = pht_fhir_client.read_query_file(query_io)

    assert isinstance(advanced_query_dict, dict)
    assert advanced_query == advanced_query_dict


def test_load_query_file(minimal_query, tmp_path):
    query_str = json.dumps(minimal_query)
    loaded_query = load_query_file(query_str)

    assert loaded_query == minimal_query

    query_bytes = query_str.encode("utf-8")

    loaded_query = load_query_file(query_bytes)

    assert loaded_query == minimal_query

    p = tmp_path / "query.json"
    p.write_text(query_str)

    loaded_query = load_query_file(p)
    assert loaded_query == minimal_query

    loaded_query = load_query_file(str(p))

    assert loaded_query == minimal_query

    with pytest.raises(ValueError):
        loaded_query = load_query_file(1234567)


def test_build_query_string(
    pht_fhir_client: PHTFhirClient, minimal_query, advanced_query
):
    string_query = "Patient?gender=male"

    query_string = build_query_string(minimal_query["query"])

    query_dict = {
        "query": {
            "resource": "Patient",
            "parameters": [
                {"variable": "gender", "condition": "male"},
                {"variable": "birthdate", "condition": "sa1980-08-12"},
            ],
            "has": [
                {
                    "resource": "Observation",
                    "property": "code",
                    "params": [
                        "I63.0",
                        "I63.1",
                        "I63.2",
                        "I63.3",
                        "I63.4",
                        "I63.5",
                        "I63.6",
                        "I63.7",
                        "I63.8",
                        "I63.9",
                    ],
                },
                {
                    "resource": "Condition",
                    "property": "code",
                    "params": [
                        "D70.0",
                        "D70.10",
                        "D70.11",
                        "D70.11",
                        "D70.12",
                        "D70.13",
                        "D70.14",
                        "D70.18",
                        "D70.19",
                        "D70.3",
                        "D70.5",
                        "D70.6",
                        "D70.7",
                    ],
                },
            ],
        },
        "data": {"output_format": "json", "filename": "patients.json"},
    }

    print(build_query_string(query_dict["query"]))

    assert string_query == query_string

    advanced_query_string = (
        "Patient?gender=male,female&birthdate=gt1980-08-12&_has:Observation:patient:code=I63.0,"
        "I63.1,I63.2,I63.3,I63.4,I63.5,I63.6,I63.7,I63.8,I63.9&_has:Condition:patient:code=D70.0"
    )

    query_string = build_query_string(advanced_query["query"])

    assert advanced_query_string == query_string


def test_query_with_client(pht_fhir_client: PHTFhirClient, minimal_query):
    query_result = pht_fhir_client.execute_query(query=minimal_query)
    print(query_result)
    assert query_result


def test_query_xml(pht_fhir_client: PHTFhirClient):
    xml_query = {
        "query": {"resource": "Patient"},
        "data": {"output_format": "xml", "filename": "conditions.xml"},
    }
    query_result = pht_fhir_client.execute_query(query=xml_query)
    assert query_result
    assert isinstance(query_result, str)

    pht_fhir_client.store_query_results(query_result, filename="fhir_results.xml")

    file_content = open("fhir_results.xml", "r").read()

    assert file_content == query_result

    # os.remove("fhir_results.xml")


def test_query_json(pht_fhir_client: PHTFhirClient):
    json_query = {
        "query": {"resource": "Patient"},
        "data": {
            "output_format": "json",
            "filename": "patients.json",
        },
    }
    query_result = pht_fhir_client.execute_query(query=json_query)
    assert len(query_result["entry"]) >= 1
    pht_fhir_client.store_query_results(query_result, filename="patients.json")
    os.remove("patients.json")
