from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, rsa

from train_lib.security.SecurityProtocol import SecurityProtocol
from train_lib.docker_util.docker_ops import *
import json
from tarfile import TarInfo
import time

IMG = "harbor.personalhealthtrain.de/pht_incoming/tb_sp_test:base"


def main():
    train_config = extract_train_config(IMG)
    print(train_config)
    sp = SecurityProtocol("tuebingen", config=train_config)
    sp.pre_run_protocol(img=IMG, private_key_path="./keys/station_tuebingen_private_key.pem")


def update_config_with_correct_signature():
    train_config = extract_train_config(IMG)
    # print(json.dumps(train_config, indent=2))
    hash = bytes.fromhex(train_config["e_h"])
    print(hash)
    with open("../test/keys/user_private_key.pem", "rb") as pk:
        private_key = serialization.load_pem_private_key(pk.read(), password=None,
                                                         backend=default_backend())
        sig = private_key.sign(hash,
                               padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                           salt_length=padding.PSS.MAX_LENGTH),
                               utils.Prehashed(hashes.SHA512())
                               )
        train_config["e_h_sig"] = sig.hex()

    # print(json.dumps(train_config, indent=2))
    archive_obj = BytesIO()

    tar = tarfile.open(fileobj=archive_obj, mode="w")
    # TODO check encoding
    data = json.dumps(train_config, indent=2).encode("utf-8")

    info = TarInfo(name="train_config.json")
    info.size = len(data)
    info.mtime = time.time()

    tar.addfile(info, BytesIO(data))
    print(tar.getmembers())
    tar.close()
    archive_obj.seek(0)
    add_archive(IMG, archive_obj, path="/opt")


if __name__ == '__main__':
    update_config_with_correct_signature()
