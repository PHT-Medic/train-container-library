from io import BytesIO
from tarfile import TarInfo
from timeit import default_timer as timer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from dotenv import find_dotenv, load_dotenv

from train_lib.docker_util.docker_ops import (
    extract_train_config,
    extract_query_json,
    add_archive,
    rebase_train_image,
)

from train_lib.security.protocol import SecurityProtocol

IMG = "harbor.personalhealthtrain.de/3ke5ymdmovwot5ac6b09i/bbc2c4a2-0436-4d5e-ad73-1867d920bf4e:latest"


def main():
    rebase_train_image("ubuntu:latest", IMG)


if __name__ == "__main__":
    # update_config_with_correct_signature()
    main()
