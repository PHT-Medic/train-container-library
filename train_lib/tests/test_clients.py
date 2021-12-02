import pytest
from dotenv import load_dotenv, find_dotenv
import hvac
import os
from train_lib.clients import PHTClient


@pytest.fixture
def vault_client():
    load_dotenv(find_dotenv())
    client = hvac.Client(
        url=os.getenv("VAULT_URL"),
        token=os.getenv("VAULT_TOKEN")
    )

    return client


@pytest.fixture
def pht_client():
    load_dotenv(find_dotenv())
    client = PHTClient(
        api_url="test",
        vault_url=os.getenv("VAULT_URL"),
        vault_token=os.getenv("VAULT_TOKEN")
    )
    return client


def test_vault_initialized(vault_client: hvac.Client):
    assert vault_client.sys.is_initialized()
    assert not vault_client.sys.is_sealed()


def test_get_user_pk(vault_client: hvac.Client, pht_client: PHTClient):
    # add a sample key
    mount = "user-secrets"
    path = "test_user"
    rsa_secret_val = "test_key"
    paillier_secret_val = "test_key"
    secret = {"data": {"rsa_public_key": secret_val, "paillier_public_key": paillier_secret_val}}
    vault_client.secrets.kv.v1.create_or_update_secret(
        mount_point=mount,
        path=path,
        secret=secret
    )

    read_secret = vault_client.kv.v1.read_secret(
        mount_point=mount,
        path=path
    )
    assert read_secret["data"]["data"]["rsa_public_key"] == rsa_secret_val
    assert read_secret["data"]["data"]["paillier_public_key"] == paillier_secret_val

    secrets = pht_client.get_user_secrets(path)

    assert secrets.rsa_public_key == secret_val

    # remove the secrets again
    vault_client.secrets.kv.v1.delete_secret(
        path=path,
        mount_point=mount
    )


def test_get_station_pk(vault_client: hvac.Client, pht_client: PHTClient):
    mount = "station-secrets"
    path = "test_station"
    secret_val = "test_key"
    secret = {"data": {"rsa_public_key": secret_val}}
    vault_client.secrets.kv.v1.create_or_update_secret(
        mount_point=mount,
        path=path,
        secret=secret
    )

    pht_client_pk = pht_client.get_station_pk(path)

    assert pht_client_pk == secret_val

    # remove the secrets again
    vault_client.secrets.kv.v1.delete_secret(
        path=path,
        mount_point=mount
    )


def test_get_multiple_station_pks(vault_client: hvac.Client, pht_client: PHTClient):
    mount = "station-secrets"
    paths = []
    secret_val = "test_key"
    secret = {"data": {"rsa_public_key": secret_val}}
    for i in range(3):
        path = f"test_station_{i}"
        paths.append(path)
        vault_client.secrets.kv.v1.create_or_update_secret(
            mount_point=mount,
            path=path,
            secret=secret
        )
    station_pks = pht_client.get_multiple_station_pks(paths)
    for path in paths:
        assert station_pks[path] == secret_val

    # clean up public keys
    for path in paths:
        vault_client.secrets.kv.v1.delete_secret(
            path=path,
            mount_point=mount
        )


def test_upload_route_to_vault(vault_client: hvac.Client, pht_client: PHTClient):
    route = [1, 2, 3]
    train_id = "test_train_route"
    mount = f"kv-pht-routes"

    pht_client.post_route_to_vault(train_id, route)

    # Cleanup route
    vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
        path=train_id,
        mount_point=mount
    )
