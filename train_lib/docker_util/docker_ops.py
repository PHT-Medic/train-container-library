import tarfile
from io import BytesIO
import os
import json

import docker


def update_archive(img: str, path: str, mode="encrypt"):
    """
    Updates an archive result files located at path using the given mode.
    Either encrypts or decrypts an archive extracted from the given image and replaces it with a copy of the archive
    containing the same files either decrypted or encrypted

    :param img:
    :param path:
    :param mode:
    :return:
    """

    files, file_members, all_members = files_from_archive(extract_archive(img, path))
    if mode == "encrypt":
        pass
    elif mode == "decrypt":
        pass
    else:
        raise ValueError(f"Unrecognized update mode: {mode}")


def extract_train_config(img: str, config_path: str = "/opt/train_config.json") -> dict:
    """
    Extract the train configuration json from the specified image and return it as a dictionary
    :param img: docker image identifier
    :param config_path: path of the config file inside the image
    :return: dictionary containing the  security values stored inside the train:config.json
    """
    config_archive = extract_archive(img, config_path)
    config_file = config_archive.extractfile("train_config.json")
    data = config_file.read()
    print(data)
    train_config = json.loads(data)
    return train_config


def files_from_archive(tar_archive: tarfile.TarFile):
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
    Extracts a file or folder at the given path from the given docker image

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


def add_archive(img: str, archive: BytesIO, path: str):
    """
    Adds a given tar archive to a given docker image at the specified path
    :param img:  identifier of the image <repository>:<tag>
    :param archive: tar archive to be added to the image
    :param path: path at which the tar archive will be added inside the image

    :return:
    """

    client = docker.from_env()
    data = client.containers.create(img)
    data.put_archive(path, archive)
    data.wait()
    # Get repository and tag for committing the container to an image
    repository, tag = img.split(":")
    data.commit(repository=repository, tag=tag)
    data.wait()


if __name__ == '__main__':
    IMG = "harbor.personalhealthtrain.de/pht_incoming/tb_sp_test:base"
    DIR = "/opt/pht_train"

    # config = extract_train_config(IMG)
