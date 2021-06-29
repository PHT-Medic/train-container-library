import json
import os
import tarfile
import time
from io import BytesIO
from unittest import mock

import cryptography.exceptions
import cryptography
import docker
import random
import pytest
from cryptography import fernet

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes

from train_lib.security.Hashing import hash_immutable_files, hash_results
from train_lib.docker_util.docker_ops import extract_train_config
from train_lib.security.SecurityProtocol import SecurityProtocol
from train_lib.security.SecurityErrors import ValidationError
from train_lib.docker_util import docker_ops


@pytest.fixture
def docker_client():
    try:
        client = docker.from_env()

    except Exception:
        client = docker.DockerClient(base_url='unix://var/run/docker.sock')

    return client


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
def test_train_image(train_config, train_file_archive, docker_client):
    # TODO test if image exists otherwise build it and pass the identifier to the test functions

    docker_file_obj = BytesIO(
        """
        FROM harbor.pht.medic.uni-tuebingen.de/pht_master/master:slim
        
        RUN mkdir /opt/pht_results
        CMD ["python", "/opt/pht_train/entrypoint.py"]
        """.encode("utf-8")
    )

    client = docker_client
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
    container.commit("sp-test", tag="base")

    return "sp-test"


def test_extract_train_config(test_train_image, train_files):
    file_names, files = train_files
    config = extract_train_config(test_train_image)

    assert config
    assert type(config) == dict

    assert config["immutable_file_list"] == file_names


def test_pre_run_protocol(test_train_image, tmpdir, key_pairs, docker_client):
    config = extract_train_config(test_train_image)

    # Check if any station can execute the pre run protocol on the raw image
    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1)
    }
    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
        sp.pre_run_protocol(img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

        # check that the session key cannot be changed
        changed_config_session_key = config.copy()
        changed_config_session_key["session_id"] = os.urandom(64).hex()

        with pytest.raises(ValidationError):
            wrong_sess_key_sp = SecurityProtocol(os.getenv("STATION_ID"), config=changed_config_session_key,
                                                 docker_client=docker_client)
            wrong_sess_key_sp.pre_run_protocol(img=test_train_image,
                                               private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

        # check that you can not change the file list
        changed_file_list_config = config.copy()
        changed_file_list_config["immutable_file_list"] = ["file_1_test.py", "r_script.r", "query.json"]

        with pytest.raises(AssertionError):
            changed_file_list_sp = SecurityProtocol(os.getenv("STATION_ID"), config=changed_file_list_config,
                                                    docker_client=docker_client)
            changed_file_list_sp.pre_run_protocol(img=test_train_image,
                                                  private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def test_files_changed_pre_run(test_train_image, tmpdir, key_pairs, docker_client):
    """
    The pre-run protocol should fail, when the content of one the immutable files has changed
    """

    # sp.pre_run_protocol(img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

    # Change the content of one the immutable files
    # changed_files_image = docker_client.containers.create(test_train_image)
    train_file_archive = docker_ops.extract_archive(test_train_image, "/opt/pht_train")
    train_files, tf_names = docker_ops.files_from_archive(train_file_archive)

    train_files = [BytesIO(f.read()) for f in train_files]
    train_files[0] = BytesIO(os.urandom(random.randint(5000, 20000)))
    # Create a new archive containing the old files and the one changed file
    archive_obj = BytesIO()
    tar = tarfile.open(fileobj=archive_obj, mode="w")
    for i, file in enumerate(train_files):
        info = tarfile.TarInfo(name=tf_names[i])
        info.size = file.getbuffer().nbytes
        info.mtime = time.time()
        tar.addfile(info, fileobj=file)

    tar.close()
    archive_obj.seek(0)

    train_container = docker_client.containers.create(test_train_image)
    train_container.put_archive("/opt/pht_train", archive_obj)
    train_container.commit(repository=test_train_image)
    train_container.wait()
    train_container.remove()

    # Get config and initialize pre run protocol

    config = extract_train_config(test_train_image)
    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1)
    }

    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
        # Security protocol should throw a validation error
        with pytest.raises(ValidationError):
            sp.pre_run_protocol(img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def test_user_signature_verification_pre_run(test_train_image, tmpdir, key_pairs, docker_client):
    config = extract_train_config(test_train_image)
    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1)
    }

    with mock.patch.dict(os.environ, environment_dict_station_1):
        # Generally invalid signature
        config["e_h_sig"] = os.urandom(64).hex()
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            sp.pre_run_protocol(img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

        user_private_key = serialization.load_pem_private_key(bytes.fromhex(key_pairs["user"]["private_key"]),
                                                              password=None,
                                                              backend=default_backend())

        # Valid signature but wrong underlying hash
        wrong_hash = hashes.Hash(hashes.SHA512(), backend=default_backend())
        wrong_hash.update(os.urandom(672))
        wrong_hash = wrong_hash.finalize()
        wrong_signature = user_private_key.sign(wrong_hash, padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                                                        salt_length=padding.PSS.MAX_LENGTH),
                                                utils.Prehashed(hashes.SHA512()))
        config["e_h_sig"] = wrong_signature.hex()
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            sp.pre_run_protocol(img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def execute_image_and_post_run_protocol(test_train_image, docker_client, tmpdir, key_pairs, station_id=3):
    init_config = extract_train_config(test_train_image)
    # Execute the image
    client = docker_client
    container = client.containers.run(image=test_train_image + ":latest", detach=True)
    exit_code = container.wait()["StatusCode"]

    assert exit_code == 0

    container.commit(test_train_image)

    # Perform post run protocol
    if station_id == 1:
        p1 = tmpdir.join("station_1_private_key.pem")
        p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

        environment_dict_station_1 = {
            "STATION_ID": "station_1",
            "STATION_PRIVATE_KEY_PATH": str(p1)
        }
        with mock.patch.dict(os.environ, environment_dict_station_1):
            sp = SecurityProtocol(os.getenv("STATION_ID"), config=init_config, docker_client=docker_client)
            sp.post_run_protocol(img=test_train_image + ":latest",
                                 private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))
    elif station_id == 2:
        p2 = tmpdir.join("station_2_private_key.pem")
        p2.write(bytes.fromhex(key_pairs["station_2"]["private_key"]))

        environment_dict_station_2 = {
            "STATION_ID": "station_2",
            "STATION_PRIVATE_KEY_PATH": str(p2)
        }
        with mock.patch.dict(os.environ, environment_dict_station_2):
            sp = SecurityProtocol(os.getenv("STATION_ID"), config=init_config, docker_client=docker_client)
            sp.post_run_protocol(img=test_train_image + ":latest",
                                 private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

    elif station_id == 3:
        p3 = tmpdir.join("station_3_private_key.pem")
        p3.write(bytes.fromhex(key_pairs["station_3"]["private_key"]))

        environment_dict_station_3 = {
            "STATION_ID": "station_3",
            "STATION_PRIVATE_KEY_PATH": str(p3)
        }
        with mock.patch.dict(os.environ, environment_dict_station_3):
            sp = SecurityProtocol(os.getenv("STATION_ID"), config=init_config, docker_client=docker_client)
            sp.post_run_protocol(img=test_train_image + ":latest",
                                 private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def test_post_run_protocol(test_train_image, tmpdir, key_pairs, docker_client):
    init_config = extract_train_config(test_train_image)
    execute_image_and_post_run_protocol(test_train_image=test_train_image, docker_client=docker_client, tmpdir=tmpdir,
                                        key_pairs=key_pairs)

    config = extract_train_config(test_train_image)

    # check that the config has changed as expected
    assert config != init_config

    # The digital signature changed
    assert config["digital_signature"] != init_config["digital_signature"]

    assert len(config["digital_signature"]) == 1

    # Check that the pre-run protocol works for the next station
    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1)
    }
    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
        sp.pre_run_protocol(img=test_train_image + ":latest", private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

    # Ensure that it does not work with a different private key

    # generate a new private key
    unregistered_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    p_wrong_key = tmpdir.join("unregistered_private_key.pem")
    p_wrong_key.write(unregistered_sk)

    assert unregistered_sk not in [bytes.fromhex(key_pairs[f"station_{s}"]["private_key"]) for s in range(1, 4)]

    environment_dict_wrong_sk = {
        "STATION_ID": "station_3",
        "STATION_PRIVATE_KEY_PATH": str(p_wrong_key)
    }
    with mock.patch.dict(os.environ, environment_dict_wrong_sk):
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)

        with pytest.raises(ValueError):
            sp.pre_run_protocol(img=test_train_image + ":latest",
                                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

    print(config["digital_signature"])

    # Change the results file to an unencrypted one and different one

    train_container = docker_client.containers.create(test_train_image)
    archive_obj = BytesIO()
    tar = tarfile.open(fileobj=archive_obj, mode="w")
    file = BytesIO(os.urandom(7634).hex().encode("utf-8"))
    info = tarfile.TarInfo(name="test_result.txt")
    info.size = file.getbuffer().nbytes
    info.mtime = time.time()
    tar.addfile(info, fileobj=file)

    tar.close()
    archive_obj.seek(0)

    train_container.put_archive("/opt/pht_results", archive_obj)

    train_container.commit(repository=test_train_image)
    train_container.wait()

    # Should throw error because the results file is not correctly encrypted
    with mock.patch.dict(os.environ, environment_dict_station_1):
        with pytest.raises(fernet.InvalidToken):
            sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
            sp.pre_run_protocol(img=test_train_image + ":latest",
                                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

    train_container = docker_client.containers.create(test_train_image)
    archive_obj = BytesIO()
    tar = tarfile.open(fileobj=archive_obj, mode="w")

    wrong_file_bytes = os.urandom(7634).hex().encode("utf-8")

    file = BytesIO(wrong_file_bytes)

    info = tarfile.TarInfo(name="test_result.txt")
    info.size = file.getbuffer().nbytes
    info.mtime = time.time()
    tar.addfile(info, fileobj=file)

    tar.close()
    archive_obj.seek(0)

    train_container.put_archive("/opt/pht_results", archive_obj)

    train_container.commit(repository=test_train_image)
    train_container.wait()

    with mock.patch.dict(os.environ, environment_dict_station_1):
        with pytest.raises(fernet.InvalidToken):
            sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
            sp.pre_run_protocol(img=test_train_image + ":latest",
                                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def test_post_run_protocol_wrong_symmetric_key(test_train_image, tmpdir, key_pairs, docker_client):
    init_config = extract_train_config(test_train_image)

    execute_image_and_post_run_protocol(test_train_image=test_train_image, docker_client=docker_client, tmpdir=tmpdir,
                                        key_pairs=key_pairs)

    config = extract_train_config(test_train_image)

    train_container = docker_client.containers.create(test_train_image)
    archive_obj = BytesIO()
    tar = tarfile.open(fileobj=archive_obj, mode="w")

    wrong_file_bytes = os.urandom(7634)

    # Encrypt the results file with a newly created symmetric key

    wrong_fernet = fernet.Fernet(fernet.Fernet.generate_key())

    wrong_file_bytes = wrong_fernet.encrypt(wrong_file_bytes)

    file = BytesIO(wrong_file_bytes)

    info = tarfile.TarInfo(name="test_result.txt")
    info.size = file.getbuffer().nbytes
    info.mtime = time.time()
    tar.addfile(info, fileobj=file)

    tar.close()
    archive_obj.seek(0)

    train_container.put_archive("/opt/pht_results", archive_obj)

    train_container.commit(repository=test_train_image)
    train_container.wait()

    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))
    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1)
    }
    with mock.patch.dict(os.environ, environment_dict_station_1):
        with pytest.raises(fernet.InvalidToken):
            sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
            sp.pre_run_protocol(img=test_train_image + ":latest",
                                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def test_pre_run_protocol_wrong_results_hash(test_train_image, tmpdir, key_pairs, docker_client):
    execute_image_and_post_run_protocol(test_train_image=test_train_image, docker_client=docker_client, tmpdir=tmpdir,
                                        key_pairs=key_pairs)

    config = extract_train_config(test_train_image)

    # Change the results hash to a random byte value
    config["e_d"] = os.urandom(673).hex()

    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1)
    }
    with mock.patch.dict(os.environ, environment_dict_station_1):
        with pytest.raises(ValidationError):
            sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
            sp.pre_run_protocol(img=test_train_image + ":latest",
                                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def test_multi_execution_protocol(test_train_image, tmpdir, key_pairs, docker_client):
    # Execute image and post run protocol for first station
    execute_image_and_post_run_protocol(test_train_image=test_train_image, docker_client=docker_client, tmpdir=tmpdir,
                                        key_pairs=key_pairs)

    # Second station

    execute_image_and_post_run_protocol(test_train_image=test_train_image, docker_client=docker_client, tmpdir=tmpdir,
                                        key_pairs=key_pairs, station_id=1)

    config = extract_train_config(test_train_image)

    # Check that the signature has been correctly updated
    assert len(config["digital_signature"]) == 2

    assert config["digital_signature"][-1]["station"] == "station_1"

    execute_image_and_post_run_protocol(test_train_image=test_train_image, docker_client=docker_client, tmpdir=tmpdir,
                                        key_pairs=key_pairs, station_id=2)

    config = extract_train_config(test_train_image)

    assert len(config["digital_signature"]) == 3


    # check that the pre run protocol works after multiple executions

    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))
    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1)
    }
    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(os.getenv("STATION_ID"), config=config, docker_client=docker_client)
        sp.pre_run_protocol(img=test_train_image + ":latest",
                            private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))
