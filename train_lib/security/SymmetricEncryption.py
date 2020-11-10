from cryptography.fernet import Fernet
from typing import List


class FileEncryptor:
    """
    Performs symmetric encryption and decryption of sensitive files belonging to the train cargo
    """

    def __init__(self, key: bytes):
        self.fernet = Fernet(key)

    def encrypt_files(self, files: List[str]):
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        print("Encrypting files..")
        for i, file in enumerate(files):
            print(f"File {i+1}/{len(files)}...", end="")
            with open(file, "rb") as f:
                encr_file = self.fernet.encrypt(f.read())
            with open(file, "wb") as ef:
                ef.write(encr_file)
            print("Done")

    def decrypt_files(self, files: List[str]):
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        print("Decrypting files..")
        for i, file in enumerate(files):
            print(f"File {i + 1}/{len(files)}...", end="")
            with open(file, "rb") as f:
                decr_file = self.fernet.decrypt(f.read())
            with open(file, "wb") as ef:
                ef.write(decr_file)
            print("Done")
