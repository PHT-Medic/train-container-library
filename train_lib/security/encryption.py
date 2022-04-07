import os
from io import BytesIO

from cryptography.fernet import Fernet
from typing import List, Union, BinaryIO
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging


class FileEncryptor:
    """
    Performs symmetric encryption and decryption of sensitive files belonging to the train cargo
    """

    def __init__(self, key: bytes, iv: bytes = None):

        if not iv:
            self.fernet = Fernet(key)
        self.key = key
        self.iv = iv if iv else os.urandom(12)

    def encrypt_files(self, files: Union[List[str], List[BinaryIO]], binary_files=False) -> Union[List[BytesIO], None]:
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        logging.info("Encrypting files..")
        if binary_files:
            encr_files = []
            for i, file in enumerate(files):
                logging.info(f"file {i + 1}/{len(files)}...")
                # Encrypt the files and convert them to bytes io file objects
                data = file.read()
                encr_files.append(BytesIO(self._encrypt(data)))
                logging.info("Done")
            return encr_files

        for i, file in enumerate(files):
            logging.info(f"File {i + 1}/{len(files)}...")
            with open(file, "rb") as f:
                encr_file = self._encrypt(f.read())
            with open(file, "wb") as ef:
                ef.write(encr_file)
            logging.info("Done")

    def decrypt_files(self, files: Union[List[str], List[BinaryIO]], binary_files=False) -> Union[List[BytesIO], None]:
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        logging.info("Decrypting files..")
        if binary_files:
            decr_files = []
            for i, file in enumerate(files):
                logging.info(f"file {i + 1}/{len(files)}...")
                data = self._decrypt(file.read())
                decr_files.append(BytesIO(data))
                logging.info("Done")
            return decr_files
        for i, file in enumerate(files):
            logging.info(f"File {i + 1}/{len(files)}...")
            with open(file, "rb") as f:
                decr_file = self._decrypt(f.read())
            with open(file, "wb") as ef:
                ef.write(decr_file)
            logging.info("Done")

    def _encrypt(self, data: bytes) -> bytes:
        aesccm = AESCCM(self.key)
        return aesccm.encrypt(self.iv, data, None)

    def _decrypt(self, data: bytes) -> bytes:
        aesccm = AESCCM(self.key)
        return aesccm.decrypt(self.iv, data, None)
