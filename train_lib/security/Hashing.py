from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import List


def hash_immutable_files(immutable_files, user_id: str, session_id: bytes):
    """
    Calculates the hash of all immutable files in the train, A, R, Q as well as the
    :param user_id:
    :param session_id:
    :param immutable_files:
    :return: byte object representing the hash of all files
    """
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(user_id.encode())
    for file in immutable_files:
        with open(file, "rb") as f:
            digest.update(f.read())
    digest.update(session_id)
    return digest.finalize()


def hash_results(result_files: List[str], session_id: bytes):
    """
    Creates a hash of the results of train execution
    :param result_files: List
    :param session_id:
    :return:
    """
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    for file in result_files:
        with open(file, "rb") as f:
            digest.update(f.read())
    digest.update(session_id)
    return digest.finalize()
