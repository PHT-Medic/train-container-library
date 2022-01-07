import pytest
from train_lib.security.train_config import TrainConfig, StationPublicKeys, EncryptedSymKey, DigitalSignature, UserPublicKeys


@pytest.fixture
def station_pks():
    station_pks = []
    for i in range(3):
        station_pks.append(
            StationPublicKeys(
                station_id=str(i),
                rsa_public_key="d9bbfd2b1198",
            )
        )
    return station_pks


@pytest.fixture
def user_keys():
    return UserPublicKeys(
        user_id="config-test-user",
        rsa_public_key="d9bbfd2b1198",
        paillier_public_key="d9bbfd2b1198",
    )


@pytest.fixture
def valid_config(station_pks, user_keys):
    return TrainConfig(
        master_image="test_image",
        user_id="config-test-user",
        proposal_id=1,
        train_id="14fc32e6-7e53-406e-b7ab-6f02c0699ade",
        session_id="d9bbfd2b119bb87f0fa7f377cffab87efed4a3ff29f87f6d57346ac83db15ec6099c63aeccd57fbdde3dae696b320fb19c922b79563c4d0a0c501de607426aa9",
        station_public_keys=station_pks,
        user_keys=user_keys,
        immutable_file_list=["entrypoint.py"],
        immutable_file_hash="d9bbfd2b1198",
        immutable_file_signature="d9bbfd2b1198",
    )


def test_config(valid_config, station_pks):
    print(station_pks)
