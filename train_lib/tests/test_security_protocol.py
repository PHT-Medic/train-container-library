import os

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from io import BytesIO, StringIO
import docker
import random

from train_lib.docker_util.docker_ops import add_archive
from train_lib.security.Hashing import hash_immutable_files, hash_results


@pytest.fixture
def key_pairs():
    # Create private keys
    station_1_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    station_2_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    station_3_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create public keys

    station_1_pk = station_1_sk.public_key()
    station_2_pk = station_2_sk.public_key()
    station_3_pk = station_3_sk.public_key()
    user_pk = user_sk.public_key()

    # serialize the keys to bytes

    station_1_sk = station_1_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    station_2_sk = station_2_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    station_3_sk = station_3_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    station_1_pk = station_1_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.TraditionalOpenSSL,
    )
    station_2_pk = station_2_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.TraditionalOpenSSL,
    )
    station_3_pk = station_3_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.TraditionalOpenSSL,
    )

    user_sk = user_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    user_pk = user_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.TraditionalOpenSSL,
    )

    key_pairs = {
        "station_1": {
            "private_key": station_1_sk,
            "public_key": station_1_pk
        },
        "station_2": {
            "private_key": station_2_sk,
            "public_key": station_2_pk
        },
        "station_3": {
            "private_key": station_3_sk,
            "public_key": station_3_pk
        },
        "user": {
            "private_key": user_sk,
            "public_key": user_pk
        },
    }

    return key_pairs


@pytest.fixture
def train_files():
    entrypoint_file_string = """
    import os
    import random
    import string


    def generate_random_text_file(filename, size):
        print("Generating file...")
        chars = ''.join([random.choice(string.ascii_letters) for i in range(size)])
        with open("/opt/pht_results/test_result.txt", 'w') as file:
            file.write(chars)


    if __name__ == '__main__':
        # 20 mb
        FILE_SIZE = 1024 * 1024 * 20
        RESULTS_DIR = "/opt/pht_results"
        FILE_NAME = "test_result.txt"
        print(f"Generating a new random file: Size={FILE_SIZE}b")

        generate_random_text_file(os.path.abspath(os.path.join(RESULTS_DIR, FILE_NAME)), FILE_SIZE)
        with open(os.path.join(RESULTS_DIR, FILE_NAME), "r") as f:
            print(f.read(200))
        print("File Generated Successfully")
    """
    entrypoint_file = BytesIO(entrypoint_file_string.encode("utf-8"))

    filenames = ["entrypoint.py", "file_1_test.py", "r_script.r", "query.json"]
    files = [BytesIO(os.urandom(random.randint(5000, 20000))) for _ in range(len(filenames))]
    files.insert(0, entrypoint_file)
    return filenames, files


@pytest.fixture
def train_config(key_pairs, train_files):
    filenames, files = train_files
    session_id = os.urandom(64)

    station_public_keys = {
        "station_1": key_pairs["station_1"]["public_key"],
        "station_2": key_pairs["station_2"]["public_key"],
        "station_3": key_pairs["station_3"]["public_key"],

    }

    user_id = "test-user-id"

    immutable_hash = hash_immutable_files(immutable_files=files, binary_files=True, user_id=user_id,
                                          session_id=session_id, ordered_file_list=filenames,
                                          immutable_file_names=filenames)

    user_private_key = serialization.load_pem_private_key(key_pairs["user"]["sk"], password=None,
                                                          backend=default_backend())
    user_signature = user_private_key.sign(immutable_hash)

    config = {
        "user_id": user_id,
        "train_id": "sp test train",
        "session_id": session_id,
        "rsa_user_public_key": key_pairs["user"]["pk"],
        "encrypted_key": None,
        "rsa_public_keys": station_public_keys,
        "e_h": immutable_hash,
        "e_h_sig": user_signature,
        "e_d": None,
        "e_d_sig": None,
        "digital_signature": None,
        "proposal_id": "1",
        "user_he_key": None,
        "immutable_file_list": filenames
    }


@pytest.fixture
def test_train_image():
    # TODO test if image exists otherwise build it and pass the identifier to the test functions

    string_docker_file = StringIO(
        """
        FROM harbor.pht.medic.uni-tuebingen.de/pht_master/master:slim
        """
    )

    client = docker.from_env()

    image, build_logs = client.images.build(fileobj=string_docker_file, tag="sp-test", rm=True, pull=True)


def test_pre_run_protocol():
    pass


def test_post_run_protocol():
    pass


def test_multi_execution_protocol():
    pass
