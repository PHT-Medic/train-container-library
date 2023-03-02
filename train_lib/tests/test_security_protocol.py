import os
import random
import tarfile
import time
from io import BytesIO
from unittest import mock

import cryptography
import cryptography.exceptions
import pytest
from cryptography import fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from train_lib.docker_util.docker_ops import (
    extract_archive,
    extract_train_config,
    files_from_archive,
)
from train_lib.security.errors import ValidationError
from train_lib.security.protocol import SecurityProtocol
from train_lib.security.train_config import TrainConfig


def test_extract_train_config(train_image, train_files):
    file_names, files = train_files
    config = extract_train_config(train_image)

    assert config
    assert isinstance(config, TrainConfig)

    assert config.file_list == file_names[:-1]


def test_get_previous_station(train_config):
    sp = SecurityProtocol(station_id="station_2", config=train_config)
    assert sp._get_previous_station().station == "station_1"


def test_pre_run_protocol(train_image, tmpdir, key_pairs, docker_client):
    config = extract_train_config(train_image)

    # Check if any station can execute the pre run protocol on the raw image
    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1),
    }
    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=config, docker_client=docker_client
        )
        sp.pre_run_protocol(
            img=train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
        )

        files, file_names = files_from_archive(
            extract_archive(train_image, "/opt/pht_train")
        )
        print(f"Files after pre run: {files}")
        for f in files:
            print(f"File: {f}")
            print(f"File content: {f.read()}")

        print(f"File names: {file_names}")

        # check that the session key cannot be changed
        changed_config_session_key = config.copy()
        changed_config_session_key.session_id = os.urandom(64).hex()

        with pytest.raises(ValidationError):
            wrong_sess_key_sp = SecurityProtocol(
                os.getenv("STATION_ID"),
                config=changed_config_session_key,
                docker_client=docker_client,
            )
            wrong_sess_key_sp.pre_run_protocol(
                img=train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
            )

        # check that you can not change the file list
        changed_file_list_config = config.copy()
        changed_file_list_config.file_list = [
            "file_1_test.py",
            "r_script.r",
            "query.json",
        ]

        with pytest.raises(ValidationError):
            changed_file_list_sp = SecurityProtocol(
                os.getenv("STATION_ID"),
                config=changed_file_list_config,
                docker_client=docker_client,
            )
            changed_file_list_sp.pre_run_protocol(
                img=train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
            )


def test_files_changed_pre_run(train_image, tmpdir, key_pairs, docker_client):
    """
    The pre-run protocol should fail, when the content of one the immutable files has changed
    """

    # sp.pre_run_protocol(img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))

    # Change the content of one the immutable files
    # changed_files_image = docker_client.containers.create(test_train_image)
    train_file_archive = extract_archive(train_image, "/opt/pht_train")
    train_files, tf_names = files_from_archive(train_file_archive)

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

    train_container = docker_client.containers.create(train_image)
    train_container.put_archive("/opt/pht_train", archive_obj)
    train_container.commit(repository=train_image)
    train_container.wait()
    train_container.remove()

    # Get config and initialize pre run protocol

    config = extract_train_config(train_image)
    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1),
    }

    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=config, docker_client=docker_client
        )
        # Security protocol should throw a validation error
        with pytest.raises(ValidationError):
            sp.pre_run_protocol(
                img=train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
            )


def test_user_signature_verification_pre_run(
    train_image, tmpdir, key_pairs, docker_client
):
    config = extract_train_config(train_image)
    p1 = tmpdir.join("station_1_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1),
    }

    with mock.patch.dict(os.environ, environment_dict_station_1):
        # Generally invalid signature
        config.signature = os.urandom(64).hex()
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=config, docker_client=docker_client
        )
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            sp.pre_run_protocol(
                img=train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
            )

        user_private_key = serialization.load_pem_private_key(
            bytes.fromhex(key_pairs["user"]["private_key"]),
            password=None,
            backend=default_backend(),
        )

        # Valid signature but wrong underlying hash
        wrong_hash = hashes.Hash(hashes.SHA512(), backend=default_backend())
        wrong_hash.update(os.urandom(672))
        wrong_hash = wrong_hash.finalize()
        wrong_signature = user_private_key.sign(
            wrong_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA512()),
        )
        config.signature = wrong_signature.hex()
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=config, docker_client=docker_client
        )
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            sp.pre_run_protocol(
                img=train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
            )


def execute_image_and_post_run_protocol(
    test_train_image, docker_client, tmpdir, key_pairs, station_id
):
    init_config = extract_train_config(test_train_image)
    # Execute the image
    client = docker_client

    # Perform post run protocol
    # if station_id == "station_1":
    p1 = tmpdir.join("station_private_key.pem")
    p1.write(bytes.fromhex(key_pairs[station_id]["private_key"]))

    environment_dict_station_1 = {
        "STATION_ID": station_id,
        "STATION_PRIVATE_KEY_PATH": str(p1),
    }
    print(f"Executing train for station: {environment_dict_station_1}")
    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=init_config, docker_client=docker_client
        )
        sp.pre_run_protocol(
            img=test_train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
        )

        container = client.containers.run(
            image=test_train_image + ":latest", detach=True
        )
        exit_code = container.wait()["StatusCode"]
        print(container.logs())
        assert exit_code == 0

        container.commit(test_train_image + ":latest")

        sp.post_run_protocol(
            img=test_train_image + ":latest",
            private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
        )
    # elif station_id == "station_2":
    #     p2 = tmpdir.join("station_2_private_key.pem")
    #     p2.write(bytes.fromhex(key_pairs["station_2"]["private_key"]))
    #
    #     environment_dict_station_2 = {
    #         "STATION_ID": "station_2",
    #         "STATION_PRIVATE_KEY_PATH": str(p2)
    #     }
    #     with mock.patch.dict(os.environ, environment_dict_station_2):
    #         sp = SecurityProtocol(os.getenv("STATION_ID"), config=init_config, docker_client=docker_client)
    #         sp.post_run_protocol(img=test_train_image + ":latest",
    #                              private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))
    #
    # elif station_id == "station_3":
    #     p3 = tmpdir.join("station_3_private_key.pem")
    #     p3.write(bytes.fromhex(key_pairs["station_3"]["private_key"]))
    #
    #     environment_dict_station_3 = {
    #         "STATION_ID": "station_3",
    #         "STATION_PRIVATE_KEY_PATH": str(p3)
    #     }
    #     with mock.patch.dict(os.environ, environment_dict_station_3):
    #         sp = SecurityProtocol(os.getenv("STATION_ID"), config=init_config, docker_client=docker_client)
    #         sp.post_run_protocol(img=test_train_image + ":latest",
    #                              private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"))


def test_digital_signature(train_image, tmpdir, key_pairs, docker_client):
    image_name = train_image + "-signature" + ":latest"

    # pre run station 1
    p1 = tmpdir.join("station_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1),
    }

    init_config = extract_train_config(train_image)

    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=init_config, docker_client=docker_client
        )
        sp.pre_run_protocol(
            img=train_image, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
        )

        container = docker_client.containers.run(image=train_image, detach=True)

        exit_code = container.wait()["StatusCode"]
        output = container.logs()

        # extract the files from the container
        # tar_stream, _ = container("/train")

        files, file_names = files_from_archive(
            extract_archive(train_image, "/opt/pht_train")
        )
        print(f"Files: {files}")
        for f in files:
            print(f"File: {f}")
            print(f"File content: {f.read()}")

        print(f"File names: {file_names}")

    print(output.decode("utf-8"))
    assert exit_code == 0

    container.commit(image_name)

    config = extract_train_config(train_image)

    assert not config.route[0].signature

    assert not config.result_hash

    # # check that the previous stop has signed the image
    # stop = next((stop for stop in config.route if stop.station == "station_1"), None)
    # assert stop.signature
    # pre run station 1
    p1 = tmpdir.join("station_private_key.pem")
    p1.write(bytes.fromhex(key_pairs["station_1"]["private_key"]))
    environment_dict_station_1 = {
        "STATION_ID": "station_1",
        "STATION_PRIVATE_KEY_PATH": str(p1),
    }

    with mock.patch.dict(os.environ, environment_dict_station_1):
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), docker_client=docker_client, config=config
        )
        sp.post_run_protocol(
            img=image_name, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
        )

    post_run_config = extract_train_config(image_name)

    assert post_run_config.route[0].signature
    assert config.result_hash


def test_post_run_protocol(train_image, tmpdir, key_pairs, docker_client):
    init_config = extract_train_config(train_image)
    execute_image_and_post_run_protocol(
        test_train_image=train_image,
        docker_client=docker_client,
        tmpdir=tmpdir,
        key_pairs=key_pairs,
        station_id="station_1",
    )

    config = extract_train_config(train_image)

    # check that the config has changed as expected
    assert config != init_config

    # The digital signature changed
    assert config.result_hash != init_config.result_hash

    assert config.result_signature != init_config.result_signature
    stop = next((stop for stop in config.route if stop.station == "station_1"), None)

    assert stop.signature.signature
    assert stop.signature.digest

    # Check that the pre-run protocol works for the next station
    p2 = tmpdir.join("station_1_private_key.pem")
    p2.write(bytes.fromhex(key_pairs["station_2"]["private_key"]))

    # set up temporary env vars
    environment_dict_station_2 = {
        "STATION_ID": "station_2",
        "STATION_PRIVATE_KEY_PATH": str(p2),
    }
    with mock.patch.dict(os.environ, environment_dict_station_2):
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=config, docker_client=docker_client
        )
        sp.pre_run_protocol(
            img=train_image + ":latest",
            private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
        )

    # Ensure that it does not work with a different private key

    # generate a new private key
    unregistered_sk = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p_wrong_key = tmpdir.join("unregistered_private_key.pem")
    p_wrong_key.write(unregistered_sk)

    assert unregistered_sk not in [
        bytes.fromhex(key_pairs[f"station_{s}"]["private_key"]) for s in range(1, 4)
    ]

    environment_dict_wrong_sk = {
        "STATION_ID": "station_2",
        "STATION_PRIVATE_KEY_PATH": str(p_wrong_key),
    }
    with mock.patch.dict(os.environ, environment_dict_wrong_sk):
        sp = SecurityProtocol(
            os.getenv("STATION_ID"), config=config, docker_client=docker_client
        )

        with pytest.raises(ValueError):
            sp.pre_run_protocol(
                img=train_image + ":latest",
                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
            )

    # Change the results file to an unencrypted one and different one

    train_container = docker_client.containers.create(train_image)
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

    train_container.commit(repository=train_image)
    train_container.wait()

    # Should throw error because the results file is not correctly encrypted
    with mock.patch.dict(os.environ, environment_dict_station_2):
        with pytest.raises(ValidationError):
            sp = SecurityProtocol(
                os.getenv("STATION_ID"), config=config, docker_client=docker_client
            )
            sp.pre_run_protocol(
                img=train_image + ":latest",
                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
            )

    train_container = docker_client.containers.create(train_image)
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

    train_container.commit(repository=train_image)
    train_container.wait()

    with mock.patch.dict(os.environ, environment_dict_station_2):
        with pytest.raises(ValidationError):
            sp = SecurityProtocol(
                os.getenv("STATION_ID"), config=config, docker_client=docker_client
            )
            sp.pre_run_protocol(
                img=train_image + ":latest",
                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
            )


def test_post_run_protocol_wrong_symmetric_key(
    train_image, tmpdir, key_pairs, docker_client
):
    execute_image_and_post_run_protocol(
        test_train_image=train_image,
        docker_client=docker_client,
        tmpdir=tmpdir,
        key_pairs=key_pairs,
        station_id="station_1",
    )

    config = extract_train_config(train_image)

    train_container = docker_client.containers.create(train_image)
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

    train_container.commit(repository=train_image)
    train_container.wait()

    p2 = tmpdir.join("station_2_private_key.pem")
    p2.write(bytes.fromhex(key_pairs["station_2"]["private_key"]))
    # set up temporary env vars
    environment_dict_station_2 = {
        "STATION_ID": "station_2",
        "STATION_PRIVATE_KEY_PATH": str(p2),
    }
    with mock.patch.dict(os.environ, environment_dict_station_2):
        with pytest.raises(ValueError):
            sp = SecurityProtocol(
                os.getenv("STATION_ID"), config=config, docker_client=docker_client
            )
            sp.pre_run_protocol(
                img=train_image + ":latest",
                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
            )


def test_pre_run_protocol_wrong_results_hash(
    train_image, tmpdir, key_pairs, docker_client
):
    execute_image_and_post_run_protocol(
        test_train_image=train_image,
        docker_client=docker_client,
        tmpdir=tmpdir,
        key_pairs=key_pairs,
        station_id="station_1",
    )

    config = extract_train_config(train_image)

    # Change the results hash to a random byte value
    wrong_hash_config = config.copy()
    wrong_hash_config.result_hash = os.urandom(52).hex()
    p2 = tmpdir.join("station_2_private_key.pem")
    p2.write(bytes.fromhex(key_pairs["station_2"]["private_key"]))
    environment_dict_station_2 = {
        "STATION_ID": "station_2",
        "STATION_PRIVATE_KEY_PATH": str(p2),
    }
    with mock.patch.dict(os.environ, environment_dict_station_2):
        with pytest.raises(ValidationError):
            sp = SecurityProtocol(
                os.getenv("STATION_ID"),
                config=wrong_hash_config,
                docker_client=docker_client,
            )
            sp.pre_run_protocol(
                img=train_image + ":latest",
                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
            )

    # wrong signature
    wrong_signature_config = config.copy()
    wrong_signature_config.result_signature = os.urandom(52).hex()
    with mock.patch.dict(os.environ, environment_dict_station_2):
        with pytest.raises(ValidationError):
            sp = SecurityProtocol(
                os.getenv("STATION_ID"),
                config=wrong_signature_config,
                docker_client=docker_client,
            )
            sp.pre_run_protocol(
                img=train_image + ":latest",
                private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH"),
            )


def test_multi_execution_protocol(train_image, tmpdir, key_pairs, docker_client):
    image_name = train_image + "-multi" + ":latest"
    container = docker_client.containers.create(train_image)
    repo, tag = image_name.split(":")
    container.commit(repository=repo, tag=tag)
    ids = ["station_1", "station_2", "station_3"]

    print("Running train image: " + image_name)
    for i, station_id in enumerate(ids):
        config = extract_train_config(image_name)
        print("Running station: " + station_id)
        p1 = tmpdir.join("station_private_key.pem")
        p1.write(bytes.fromhex(key_pairs[station_id]["private_key"]))
        environment_dict_station = {
            "STATION_ID": station_id,
            "STATION_PRIVATE_KEY_PATH": str(p1),
        }
        with mock.patch.dict(os.environ, environment_dict_station):
            sp = SecurityProtocol(
                os.getenv("STATION_ID"), docker_client=docker_client, config=config
            )
            sp.pre_run_protocol(
                img=image_name, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
            )
            container = docker_client.containers.run(image=image_name, detach=True)
            exit_code = container.wait()["StatusCode"]

            logs = container.logs()
            print(logs)
            assert exit_code == 0

            container.commit(image_name)
            container.wait()

            # config = extract_train_config(image_name)

            sp = SecurityProtocol(
                os.getenv("STATION_ID"), docker_client=docker_client, config=config
            )
            sp.post_run_protocol(
                img=image_name, private_key_path=os.getenv("STATION_PRIVATE_KEY_PATH")
            )

            post_run_config = extract_train_config(image_name)

            assert post_run_config.route[i].signature
