from typing import BinaryIO, List, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from loguru import logger


def hash_immutable_files(
    immutable_files: Union[List[BinaryIO], List[str]],
    user_id: str,
    session_id: bytes,
    binary_files=False,
    ordered_file_list: list = None,
    immutable_file_names: List[str] = None,
    query: bytes = None,
):
    """
    Calculates the hash of all immutable files in the train, A, R, Q as well as the
    :param binary_files: boolean parameter indicating whether the files are binary files or file paths
    :param user_id:
    :param session_id:
    :param immutable_files:
    :return: byte object representing the hash of all files
    """

    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(user_id.encode("utf-8"))
    query_file = None
    if binary_files:
        if immutable_file_names:
            for f in ordered_file_list:
                logger.trace(f"Hashing file {f}")
                # TODO ugly workaround fix this
                if f.startswith("./"):
                    f = f[2:]

                index = immutable_file_names.index(f)
                if f == "query.json":
                    logger.debug("Found query file")
                    query_file = immutable_files[index].read()
                    continue
                data = immutable_files[index].read()
                digest.update(data)
        else:
            for file in immutable_files:
                digest.update(file.read())
    else:
        for file in ordered_file_list:
            with open(file, "rb") as f:
                digest.update(f.read())

    digest.update(session_id)
    if query_file:
        digest.update(query_file)
    if query:
        logger.debug("Adding query to hash")
        digest.update(query)
    return digest.finalize()


def hash_results(
    result_files: Union[List[str], List[BinaryIO]],
    session_id: bytes,
    binary_files=False,
):
    """
    Creates a hash of the results of train execution
    :param result_files: List
    :param session_id:
    :return:
    """
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    if binary_files:
        for file in result_files:
            data = file.read()
            digest.update(data)
    else:
        for file in result_files:
            with open(file, "rb") as f:
                digest.update(f.read())
    digest.update(session_id)
    return digest.finalize()
