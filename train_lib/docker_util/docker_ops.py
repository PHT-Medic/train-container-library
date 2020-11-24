import tarfile
from io import BytesIO
import os
import json

import docker


def update_results(img: str, path: str, mode="encrypt"):
    """
    Updates the result files located at path using the given mode.
    Either encrypts or decrypts an archive extracted from the given image and replaces it with a copy of the archive
    containing the same files either decrypted or encrypted

    :param img:
    :param path:
    :param mode:
    :return:
    """

    files, file_members, all_members = _files_from_archive(extract_archive(img, path))
    if mode == "encrypt":
        pass
    elif mode == "decrypt":
        pass
    else:
        raise ValueError(f"Unrecognized update mode: {mode}")


def extract_train_config(img, config_path: str = "/opt/train_config.json") -> dict:
    config_archive = extract_archive(img, config_path)
    config_file = config_archive.extractfile("train_config.json")
    config = json.loads(config_file.read())
    print(config)


def _files_from_archive(tar_archive: tarfile.TarFile):
    """
    Extracts only the actual files from the given tarfile

    :param tar_archive: the tar archive from which to extract the files
    :return: List of file object extracted from the tar archive
    """

    file_members = []
    for member in tar_archive.getmembers():
        if member.isreg():  # skip if the TarInfo is not files
            file_members.append(member)

    files = []
    for file_member in file_members:
        files.append(tar_archive.extractfile(file_member))
    return files, file_members, tar_archive.getmembers()


def extract_archive(img: str, extract_path: str) -> tarfile.TarFile:
    """
    Extracts a file or folder at the given path from the given container

    :param img: identifier of the img to extract the file from
    :param extract_path: path of the file or directory to extract from the container
    :return: tar archive containing the the extracted path
    """
    client = docker.from_env()
    data = client.containers.create(img)
    stream, stat = data.get_archive(extract_path)
    file_obj = BytesIO()
    for i in stream:
        file_obj.write(i)
    file_obj.seek(0)
    tar = tarfile.open(mode="r", fileobj=file_obj)
    return tar


if __name__ == '__main__':
    IMG = "harbor.personalhealthtrain.de/pht_incoming/tb_sp_test:base"
    DIR = "/opt/pht_train"

    config = extract_train_config(IMG)
