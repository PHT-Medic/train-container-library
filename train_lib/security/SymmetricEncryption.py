from io import BytesIO

from cryptography.fernet import Fernet
from typing import List, Union, BinaryIO


class FileEncryptor:
    """
    Performs symmetric encryption and decryption of sensitive files belonging to the train cargo
    """

    def __init__(self, key: bytes):
        self.fernet = Fernet(key)

    def encrypt_files(self, files: Union[List[str], List[BinaryIO]], binary_files=False):
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        print("Encrypting files..")
        if binary_files:
            encr_files = []
            for i, file in enumerate(files):
                print(f"Encrypting file {i}/{len(files)}...")
                # Encrypt the files and convert them to bytes io file objects
                data = file.read()
                encr_files.append(BytesIO(self.fernet.encrypt(data)))
            return encr_files

        for i, file in enumerate(files):
            print(f"File {i+1}/{len(files)}...", end="")
            with open(file, "rb") as f:
                encr_file = self.fernet.encrypt(f.read())
            with open(file, "wb") as ef:
                ef.write(encr_file)
            print("Done")

    def decrypt_files(self, files: Union[List[str], List[BinaryIO]], binary_files=False):
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        print("Decrypting files..")
        if binary_files:
            # TODO evaluate memory consumption
            decr_files = []
            for file in files:
                data = self.fernet.decrypt(file.read())
                decr_files.append(BytesIO(data))
            return decr_files
        for i, file in enumerate(files):
            print(f"File {i + 1}/{len(files)}...", end="")
            with open(file, "rb") as f:
                decr_file = self.fernet.decrypt(f.read())
            with open(file, "wb") as ef:
                ef.write(decr_file)
            print("Done")
