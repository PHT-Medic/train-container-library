import json
import os
import tarfile
import time
from io import BytesIO
from unittest import mock

import docker
import random
import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes


from train_lib.security.Hashing import hash_immutable_files, hash_results
from train_lib.docker_util.docker_ops import extract_train_config
from train_lib.security.SecurityProtocol import SecurityProtocol


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
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    station_2_pk = station_2_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    station_3_pk = station_3_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    user_sk = user_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    user_pk = user_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_pairs = {
        "station_1": {
            "private_key": station_1_sk.hex(),
            "public_key": station_1_pk.hex()
        },
        "station_2": {
            "private_key": station_2_sk.hex(),
            "public_key": station_2_pk.hex()
        },
        "station_3": {
            "private_key": station_3_sk.hex(),
            "public_key": station_3_pk.hex()
        },
        "user": {
            "private_key": user_sk.hex(),
            "public_key": user_pk.hex()
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
    files = [BytesIO(os.urandom(random.randint(5000, 20000))) for _ in range(len(filenames) - 1)]
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

    user_private_key = serialization.load_pem_private_key(bytes.fromhex(key_pairs["user"]["private_key"]),
                                                          password=None,
                                                          backend=default_backend())
    user_signature = user_private_key.sign(immutable_hash,
                                           padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                                       salt_length=padding.PSS.MAX_LENGTH),
                                           utils.Prehashed(hashes.SHA512()))

    config = {
        "user_id": user_id,
        "train_id": "sp test train",
        "session_id": session_id.hex(),
        "rsa_user_public_key": key_pairs["user"]["public_key"],
        "encrypted_key": None,
        "rsa_public_keys": station_public_keys,
        "e_h": immutable_hash.hex(),
        "e_h_sig": user_signature.hex(),
        "e_d": None,
        "e_d_sig": None,
        "digital_signature": None,
        "proposal_id": "1",
        "user_he_key": None,
        "immutable_file_list": filenames
    }

    return config


@pytest.fixture
def train_file_archive(train_files):
    archive = BytesIO()
    tar = tarfile.open(fileobj=archive, mode="w")

    file_names, files = train_files
    print(file_names)
    print(files)
    for i, file in enumerate(files):
        file.seek(0)
        f = tarfile.TarInfo(name=file_names[i])
        f.size = file.getbuffer().nbytes
        f.mtime = time.time()
        # add config data and reset the archive
        tar.addfile(f, file)

    tar.close()
    archive.seek(0)

    return archive


@pytest.fixture
def test_train_image(train_config, train_file_archive):
    # TODO test if image exists otherwise build it and pass the identifier to the test functions

    docker_file_obj = BytesIO(
        """
        FROM harbor.pht.medic.uni-tuebingen.de/pht_master/master:slim
        
        RUN mkdir /opt/pht_results
        CMD ["python", "/opt/pht_train/entrypoint.py"]
        """.encode("utf-8")
    )

    client = docker.from_env()
    image, build_logs = client.images.build(fileobj=docker_file_obj, tag="sp-test", rm=True, pull=True)

    # Create the train_config archive

    config_archive = BytesIO()
    tar = tarfile.open(fileobj=config_archive, mode="w")
    # transform  to bytesIo containing binary json data
    config = BytesIO(json.dumps(train_config, indent=2).encode("utf-8"))

    # Create TarInfo Object based on the data
    config_file = tarfile.TarInfo(name="train_config.json")
    config_file.size = config.getbuffer().nbytes
    config_file.mtime = time.time()
    # add config data and reset the archive
    tar.addfile(config_file, config)
    tar.close()
    config_archive.seek(0)

    container = client.containers.create(image)
    container.put_archive("/opt", config_archive)

    # add train file archive
    container.put_archive("/opt/pht_train", train_file_archive)

    container.commit("sp-test", tag="latest")

    return "sp-test"


def test_extract_train_config(test_train_image):
    config = extract_train_config(test_train_image)

    assert config
    assert type(config) == dict


def test_pre_run_protocol(test_train_image, tmpdir, key_pairs):
    config = extract_train_config(test_train_image)
    p = tmpdir.join("station_private_key.pem")
    p.write(bytes.fromhex(key_pairs["station_1"]["public_key"]))

    environment_dict = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p)
    }
    with mock.patch.dict(os.environ, environment_dict):
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config)
        print(os.getenv("STATION_PRIVATE_KEY_PATH"))
        sp.pre_run_protocol(img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))





def test_post_run_protocol():
    pass


def test_multi_execution_protocol():
    pass
