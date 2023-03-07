import json
import os
import random
import tarfile
import time
from io import BytesIO

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import docker
from train_lib.security.encryption import FileEncryptor
from train_lib.security.hashing import hash_immutable_files
from train_lib.security.train_config import TrainConfig


@pytest.fixture
def docker_client():
    try:
        client = docker.from_env()

    except Exception:
        client = docker.DockerClient(base_url="unix://var/run/docker.sock")

    return client


@pytest.fixture
def key_pairs():
    # Create private keys
    station_1_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    station_2_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    station_3_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    builder_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create public keys

    station_1_pk = station_1_sk.public_key()
    station_2_pk = station_2_sk.public_key()
    station_3_pk = station_3_sk.public_key()
    user_pk = user_sk.public_key()
    builder_pk = builder_sk.public_key()

    # serialize the keys to bytes

    station_1_sk = station_1_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    station_2_sk = station_2_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    station_3_sk = station_3_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
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
        encryption_algorithm=serialization.NoEncryption(),
    )

    user_pk = user_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    builder_sk = builder_sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    builder_pk = builder_pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_pairs = {
        "station_1": {
            "private_key": station_1_sk.hex(),
            "public_key": station_1_pk.hex(),
        },
        "station_2": {
            "private_key": station_2_sk.hex(),
            "public_key": station_2_pk.hex(),
        },
        "station_3": {
            "private_key": station_3_sk.hex(),
            "public_key": station_3_pk.hex(),
        },
        "user": {"private_key": user_sk.hex(), "public_key": user_pk.hex()},
        "builder": {"private_key": builder_sk.hex(), "public_key": builder_pk.hex()},
    }

    return key_pairs


@pytest.fixture
def train_files(query_json):
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
    FILE_SIZE = 1024 * 1024
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
    files = [
        BytesIO(os.urandom(random.randint(100, 500))) for _ in range(len(filenames) - 2)
    ]
    files.insert(0, entrypoint_file)
    files.append(query_json)
    return filenames, files


@pytest.fixture
def symmetric_key():
    return b"\xcc\xd3\xd7V\xa5J\x15a-\xa0\xa2+\x88_=X\xb1\xd2=\x9f{!\x95\x07\x14\xf2z\x83WL\x8f\xe4"


@pytest.fixture
def encrypted_symmetric_key(key_pairs, symmetric_key):
    station_1_pk = serialization.load_pem_public_key(
        bytes.fromhex(key_pairs["station_1"]["public_key"]),
        backend=default_backend(),
    )

    encrypted_key = station_1_pk.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None,
        ),
    )

    return encrypted_key


@pytest.fixture
def query_json():
    minimal_query = {
        "query": {
            "resource": "Patient",
            "parameters": [{"variable": "gender", "condition": "male"}],
        },
        "data": {
            "output_format": "json",
            "filename": "patients.json",
            "variables": ["id", "birthDate", "gender"],
        },
    }
    # transform  to BytesIo containing binary json data
    query = BytesIO(json.dumps(minimal_query, indent=2).encode("utf-8"))

    return query


@pytest.fixture
def train_config(key_pairs, train_files, encrypted_symmetric_key):
    filenames, files = train_files
    session_id = os.urandom(64)

    station_public_keys = {
        "station_1": key_pairs["station_1"]["public_key"],
        "station_2": key_pairs["station_2"]["public_key"],
        "station_3": key_pairs["station_3"]["public_key"],
    }

    user_id = "test-user-id"
    print("filenames", filenames)
    immutable_hash = hash_immutable_files(
        immutable_files=files,
        binary_files=True,
        user_id=user_id,
        session_id=session_id,
        ordered_file_list=filenames,
        immutable_file_names=filenames,
    )

    print("Immutable Hash: ", immutable_hash)
    # create user signature
    user_private_key = serialization.load_pem_private_key(
        bytes.fromhex(key_pairs["user"]["private_key"]),
        password=None,
        backend=default_backend(),
    )
    user_signature = user_private_key.sign(
        immutable_hash, padding.PKCS1v15(), hashes.SHA512()
    )

    # create builder signature
    builder_private_key = serialization.load_pem_private_key(
        bytes.fromhex(key_pairs["builder"]["private_key"]),
        password=None,
        backend=default_backend(),
    )

    # create hash of user signature and immutable hash

    build_sig_data = immutable_hash.hex() + user_signature.hex()

    # sign the hash with builder private key
    builder_signature = builder_private_key.sign(
        bytes.fromhex(build_sig_data), padding.PKCS1v15(), hashes.SHA512()
    )
    filenames_no_query = filenames[:-1]

    config_dict = {
        "@id": "test_train_id",
        "session_id": session_id.hex(),
        "proposal_id": "test_proposal_id",
        "source": {
            "type": "docker_repository",
            "tag": "latest",
            "address": "test_repository",
        },
        "creator": {
            "id": user_id,
            "rsa_public_key": key_pairs["user"]["public_key"],
        },
        "build": {
            "signature": builder_signature.hex(),
            "rsa_public_key": key_pairs["builder"]["public_key"],
        },
        "route": [
            {
                "station": "station_1",
                "eco_system": "tue",
                "rsa_public_key": station_public_keys["station_1"],
                "index": 0,
                "encrypted_key": encrypted_symmetric_key.hex(),
            },
            {
                "station": "station_2",
                "rsa_public_key": station_public_keys["station_2"],
                "eco_system": "tue",
                "index": 1,
            },
            {
                "station": "station_3",
                "rsa_public_key": station_public_keys["station_3"],
                "eco_system": "tue",
                "index": 2,
            },
        ],
        "file_list": filenames_no_query,
        "hash": immutable_hash.hex(),
        "signature": user_signature.hex(),
        "@context": {"link": "https://www.w3.org/2018/credentials/v1"},
    }

    return TrainConfig(**config_dict)


@pytest.fixture
def train_file_archive(train_files, symmetric_key):
    archive = BytesIO()
    tar = tarfile.open(fileobj=archive, mode="w")

    file_names, files = train_files
    # init encryptor with symmetric key
    encryptor = FileEncryptor(symmetric_key)
    # encrypt all the files
    encrypted_files = encryptor.encrypt_files(files, binary_files=True)

    for i, file in enumerate(encrypted_files):
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
def master_image():
    return "dev-harbor.personalhealthtrain.de/master/python/base:latest"


@pytest.fixture
def train_image(
    train_config: TrainConfig, train_file_archive, docker_client, master_image
):
    docker_file_obj = BytesIO(
        f"""
        FROM {master_image}
        RUN mkdir /opt/pht_results && mkdir /opt/pht_train
        CMD ["python", "/opt/pht_train/entrypoint.py"]
        """.encode(
            "utf-8"
        )
    )

    client = docker_client
    image, build_logs = client.images.build(
        fileobj=docker_file_obj, tag="sp-test", rm=True, pull=True
    )

    # Create the train_config archive

    config_archive = BytesIO()
    tar = tarfile.open(fileobj=config_archive, mode="w")
    # transform  to bytesIo containing binary json data
    config = BytesIO(train_config.json(indent=2, by_alias=True).encode("utf-8"))

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
    container.commit("sp-test", tag="base")

    return "sp-test"
