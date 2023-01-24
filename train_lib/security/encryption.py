import logging
import os
from io import BytesIO
from typing import BinaryIO, List, Union

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IV_LENGTH = 16


class FileEncryptor:
    """
    Performs symmetric encryption and decryption of sensitive files belonging to the train cargo
    """

    def __init__(self, key: bytes):
        self.key = key
        self.iv = os.urandom(IV_LENGTH)

    def encrypt_files(
        self, files: Union[List[str], List[BinaryIO]], binary_files=False
    ) -> Union[List[BytesIO], None]:
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
                encr_files.append(BytesIO(self._encrypt_aes(data)))
                logging.info("Done")
            return encr_files

        for i, file in enumerate(files):
            logging.info(f"File {i + 1}/{len(files)}...")
            with open(file, "rb") as f:
                encr_file = self._encrypt_aes(f.read())
            with open(file, "wb") as ef:
                ef.write(encr_file)
            logging.info("Done")

    def decrypt_files(
        self, files: Union[List[str], List[BinaryIO]], binary_files=False
    ) -> Union[List[BytesIO], None]:
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        logging.info("Decrypting files..")
        if binary_files:
            decr_files = []
            for i, file in enumerate(files):
                logging.info(f"file {i + 1}/{len(files)}...")
                data = self._decrypt_aes(file.read())
                decr_files.append(BytesIO(data))
                logging.info("Done")
            return decr_files
        for i, file in enumerate(files):
            logging.info(f"File {i + 1}/{len(files)}...")
            with open(file, "rb") as f:
                decr_file = self._decrypt_aes(f.read())
            with open(file, "wb") as ef:
                ef.write(decr_file)
            logging.info("Done")

    def decrypt_file(self, file: BinaryIO) -> BytesIO:
        """
        Decrypt the given file using symmetric encryption
        :return:
        """
        file.seek(0)
        data = self._decrypt_aes(file.read())
        return BytesIO(data)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt the given data using symmetric encryption
        :return:
        """
        return self._decrypt_aes(data)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt the given data using symmetric encryption
        :return:
        """
        return self._encrypt_aes(data)

    def encrypt_file(self, file: BinaryIO) -> BytesIO:
        """
        Encrypt the given file using symmetric encryption
        :return:
        """
        data = self._encrypt_aes(file.read())
        return BytesIO(data)

    def _encrypt_aes(self, data: bytes) -> bytes:

        padder = padding.PKCS7(128).padder()

        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        encryptor = cipher.encryptor()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return self.iv + encrypted

    def _decrypt_aes(self, data: bytes) -> bytes:

        iv = data[:IV_LENGTH]
        data = data[IV_LENGTH:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        decrypted = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()

        unpadded_data = unpadder.update(decrypted) + unpadder.finalize()
        return unpadded_data
