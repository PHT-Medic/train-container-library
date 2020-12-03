from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, rsa

from train_lib.security.SecurityProtocol import SecurityProtocol
from train_lib.docker_util.docker_ops import *
import json
from tarfile import TarInfo
from timeit import default_timer as timer
import time
from dotenv import find_dotenv, load_dotenv

IMG = "harbor.personalhealthtrain.de/pht_incoming/22:base"


def main():
    load_dotenv(find_dotenv())
    train_config = extract_train_config(IMG)
    # Execute pre run protocol
    sp = SecurityProtocol("2", config=train_config)
    start = timer()
    sp.pre_run_protocol(img=IMG, private_key_path="./keys/station_aachen_private_key.pem")
    print(f"Pre run execution time: {timer() - start}")

    # Run the image
    start = timer()
    client = docker.from_env()
    container = client.containers.run(IMG, detach=True)
    container.wait()
    print(container.logs())
    repository, tag = IMG.split(":")
    container.commit(repository=repository, tag=tag)
    print(f"Train execution time: {timer() - start}")

    # Post run
    start = timer()
    sp.post_run_protocol(img=IMG, private_key_path=os.path.abspath("./keys/station_aachen_private_key.pem"))
    print(f"Post run execution time: {timer() - start}")


def update_config_with_correct_signature():
    train_config = extract_train_config(IMG)
    train_hash = bytes.fromhex(train_config["e_h"])
    with open("../test/keys/user_private_key.pem", "rb") as pk:
        private_key = serialization.load_pem_private_key(pk.read(), password=None,
                                                         backend=default_backend())
        sig = private_key.sign(train_hash,
                               padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                           salt_length=padding.PSS.MAX_LENGTH),
                               utils.Prehashed(hashes.SHA512())
                               )
        train_config["e_h_sig"] = sig.hex()

    # Create archive containing the updated configuration file
    archive_obj = BytesIO()

    tar = tarfile.open(fileobj=archive_obj, mode="w")
    data = json.dumps(train_config, indent=2).encode("utf-8")

    # Create TarInfo Object based on the data
    info = TarInfo(name="train_config.json")
    info.size = len(data)
    info.mtime = time.time()

    tar.addfile(info, BytesIO(data))
    tar.close()
    archive_obj.seek(0)
    add_archive(IMG, archive_obj, path="/opt")


if __name__ == '__main__':
    # update_config_with_correct_signature()
    main()
