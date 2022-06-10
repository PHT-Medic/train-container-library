import pprint

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils, rsa

from train_lib.security.protocol import SecurityProtocol
from train_lib.docker_util.docker_ops import *
import json
from tarfile import TarInfo
from timeit import default_timer as timer
import time
from dotenv import find_dotenv, load_dotenv
from train_lib.security.hashing import hash_immutable_files

IMG = "staging-harbor.tada5hi.net/10fqi2nugnog5nak0ylec/79a0c3ba-0d42-4e97-b501-470b34306dce:latest"


def main():
    load_dotenv(find_dotenv())
    train_config = extract_train_config(IMG)
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    pprint.pp(train_config)



    query = extract_query_json(IMG)
    print(query.decode("utf-8"))

    digest.update(query)
    print(digest.finalize().hex())
    print(type(query))
    with open("query.json", "wb") as f:
        f.write(query)

    with open("query.json", "rb") as f:
        query_read = f.read()

    print(query_read == query)
    # Execute pre run protocol
    sp = SecurityProtocol("10fqi2nugnog5nak0ylec", config=train_config)
    start = timer()
    sp.pre_run_protocol(img=IMG, private_key_path="test-key.pem")
    print(f"Pre run execution time: {timer() - start}")

    # # Run the image
    # start = timer()
    # client = docker.from_env()
    # container = client.containers.run(IMG, detach=True)
    # container.wait()
    # print(container.logs())
    # repository, tag = IMG.split(":")
    # container.commit(repository=repository, tag=tag)
    # print(f"Train execution time: {timer() - start}")
    #
    # # Post run
    # start = timer()
    # sp.post_run_protocol(img=IMG, private_key_path=os.path.abspath("./keys/station_aachen_private_key.pem"))
    # print(f"Post run execution time: {timer() - start}")


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

    # img = "harbor.personalhealthtrain.de/pht_incoming/c1623f6a-e734-49e2-b1c1-a0237d5521b4:latest"
    # config = extract_train_config(img)
    # sp = SecurityProtocol(station_id="1", config=config)
    # # files = sp._parse_files(train_dir)
    # # print(files)
    #
    # sp.pre_run_protocol("harbor.personalhealthtrain.de/pht_incoming/c1623f6a-e734-49e2-b1c1-a0237d5521b4",
    #                     "./keys/user_private_key.pem")
    #
    # file_order = ["final_train/auto_augment.py", "final_train/central_entrypoint.py", "final_train/entrypoint.py",
    #               "final_train/eval.py", "final_train/models.py", "final_train/test.py", "final_train/train.py",
    #               "final_train/utils.py", "final_train/__init__.py", "final_train/pc_cfgs/example.py",
    #               "final_train/pc_cfgs/__init__.py", "final_train/cfgs/effb6_central_multigpu.py"]
    #
    # session_id = "7ba497dbcb48111f22b406d4a026f6d22c1e71f52d49ac980ac897882124d6f4f6cb5dba326670b960278d6fbdb7369f49a2c2d20580c62c6740c0b5849d9e29"
    # # files_hash = hash_immutable_files(
    # #     immutable_files=files,
    # #     user_id="3",
    # #     session_id=bytes.fromhex(session_id),
    # #     binary_files=False,
    # #     ordered_file_list=file_order)
    # #
    # # print("File hash", files_hash.hex())
    # #
    # archive = extract_archive(img="360be6e2e92a", extract_path="/opt/pht_train")
    # # print(archive.getmembers())
    #
    # archive_files, names = files_from_archive(archive)
    # file_info = zip(archive_files, names)
    # for f in file_info:
    #     print(f)
    # file_hash = hash_immutable_files(archive_files, user_id="3", session_id=bytes.fromhex(session_id),
    #                                  binary_files=True, ordered_file_list=file_order,
    #                                  immutable_file_names=names)
    # print(file_hash.hex())
