from io import BytesIO
from typing import List, Union
import os
import docker
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from uuid import uuid4


def build_test_train(master_img: str = "harbor.pht.medic.uni-tuebingen.de/pht_master/master:slim",
                     executable: str = "python",
                     train_image_name: str = None,
                     train_files: List[Union[BytesIO, str]] = None,
                     train_dir: Union[str, os.PathLike] = None,
                     entrypoint_file: str = None,
                     private_key: Union[str, os.PathLike, BytesIO, RSAPrivateKey] = None,
                     user_private_key: Union[str, os.PathLike, BytesIO, RSAPrivateKey] = None,
                     security_protocol: bool = False):
    client = docker.from_env()

    if not (train_files or train_dir):
        raise ValueError("Either files or a directory containing train files need to be set.")

    docker_file = _make_docker_file(master_img, executable, entrypoint_file)

    if not train_image_name:
        train_image_name = f"test_train/{uuid4()}"

    train_img = build_train_image(client=client, docker_file=docker_file, train_files=train_files, train_dir=train_dir,
                                  train_image_name=train_image_name, private_key=private_key,
                                  user_private_key=user_private_key, security_protocol=security_protocol)


def build_train_image(client: docker.DockerClient,
                      docker_file: BytesIO,
                      train_files: List[Union[BytesIO, str]] = None,
                      train_dir: Union[str, os.PathLike] = None,
                      train_image_name: str = None,
                      private_key: Union[str, os.PathLike, BytesIO, RSAPrivateKey] = None,
                      user_private_key: Union[str, os.PathLike, BytesIO, RSAPrivateKey] = None,
                      security_protocol: bool = False
                      ):
    img, build_logs = client.images.build(fileobj=docker_file, tag=train_image_name, rm=True, pull=True)

    if security_protocol:
        config = _make_train_config(private_key, user_private_key)

    return img


def _add_train_files(img, train_files: List[Union[BytesIO, str]] = None, train_dir: Union[str, os.PathLike] = None):
    pass


def _make_train_config(private_key: Union[str, os.PathLike, BytesIO, RSAPrivateKey],
                       user_private_key: Union[str, os.PathLike, BytesIO, RSAPrivateKey]):
    if not private_key:
        # todo generate new private/public key and save/print it
        pass

    if not user_private_key:
        # todo generate new private key and
        pass


def _generate_key_pair(output_format: str = "pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if output_format == "pem":
        return private_bytes, public_bytes

    elif output_format == "hex":

        return private_bytes.hex(), public_bytes.hex()

    return private_key, public_key


def _make_docker_file(master_img: str, executable: str, entrypoint_file: str = None) -> BytesIO:
    if not entrypoint_file:
        entrypoint_file = "/opt/pht_train/entrypoint.py"
    docker_file_obj = BytesIO(
        f"""
        FROM {master_img}
        
        RUN mkdir /opt/pht_results && mkdir /opt/pht_results && chmod -R 755 /opt/pht_train
        CMD ["{executable}", "{entrypoint_file}"]
        """.encode("utf-8")
    )

    return docker_file_obj


if __name__ == '__main__':
    build_test_train()
