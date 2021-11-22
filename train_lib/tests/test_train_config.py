import pytest
from train_lib.security.train_config import TrainConfig, StationPK, EncryptedSymKey, DigitalSignature


@pytest.fixture
def station_pk():

    return StationPK(
        station_id=1,
        public_key="public_key"

    )


@pytest.fixture
def valid_config():

    return TrainConfig(
        master_image="test_image",
        user_id=1,
        proposal_id=1,
        train_id="14fc32e6-7e53-406e-b7ab-6f02c0699ade",
        session_id="d9bbfd2b119bb87f0fa7f377cffab87efed4a3ff29f87f6d57346ac83db15ec6099c63aeccd57fbdde3dae696b320fb19c922b79563c4d0a0c501de607426aa9",

    )
