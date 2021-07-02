from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import List, Union, BinaryIO
import os


def measure_runtime(time_now):
    """
    Calculates the hash of all immutable files in the train, A, R, Q as well as the
    :param binary_files: boolean parameter indicating whether the files are binary files or file paths
    :param user_id:
    :param session_id:
    :param immutable_files:
    :return: byte object representing the hash of all files
    """
    runtime = 0


    return runtime