from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
import pickle


class KeyManager:
    """
    Class that creates, stores and if necessary updates all relevant keys for symmetric and asymmetric encryption
    """

    def __init__(self, keys):
        self.keys = keys

    def save_keyfile(self):
        return pickle.dumps(self.keys)

    def get_security_param(self, param: str):
        """
        Returns a parameter from the associated keyfile
        :param param:
        :return: value of the specified parameter
        """
        return self.keys[param]

    def set_security_param(self, param: str, value):
        """
        Updates a parameter in the keyfile with the given value
        :param param: the parameter to update
        :param value: new value for param
        :return:
        """
        self.keys[param] = value

    @staticmethod
    def generate_symmetric_key():
        """
        Create a symmetric fernet key for encrypting sensitive files
        :return:
        """
        return Fernet.generate_key()

    def get_sym_key(self):
        """
        Decrypts the symmetric key using a stored private key
        :return: symmetric fernet key used to encrypt and decrypt files
        """
        private_key = self.load_private_key("RSA_STATION_PRIVATE_KEY")
        encrypted_sym_key = self.get_security_param("encrypted_key")
        symmetric_key = private_key.decrypt(encrypted_sym_key,
                                            padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                algorithm=hashes.SHA512(),
                                                label=None
                                            )
                                            )
        return symmetric_key

    def generate_encrypted_keys(self, symmetric_key):
        """
        Generates a dictionary containing the symmetric key used to encrypt files, encrypted with the public keys of all
        stations on the route
        :return: Dictionary consisting of  key = Station Id, value = Symmetric key encrypted with public key of station Id
        """
        enc_keys = {}
        for station, pk in self.keys["rsa_public_keys"]:
            enc_keys[station] = self.encrypt_symmetric_key(symmetric_key, pk)
        return enc_keys

    def encrypt_symmetric_key(self, sym_key, public_key):
        """
        Encrypt the symmetric key with the provided public key
        :return:
        """
        public_key = self.load_public_key(public_key)
        encrypted_key = public_key.encrypt(sym_key,
                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                        algorithm=hashes.SHA512(),
                                                        label=None)
                                           )
        return encrypted_key


    @staticmethod
    def load_private_key(key_path):
        """
        Loads the private key from the path provided provided in the environment variables of the currently
        running image
        :param key_path: path to the file storing the private key
        :return: a private key object either rsa or ec
        """
        # TODO get user/station key from station config via airflow
        with open(os.environ[key_path], "rb") as pk:
            private_key = serialization.load_pem_private_key(pk.read(),
                                                             password=None,
                                                             backend=default_backend())
        return private_key

    @staticmethod
    def load_public_key(key: str):
        """
        Loads a public key
        :param key: string representation of a public key
        :return: public key object for asymmetric encryption
        """
        public_key = serialization.load_pem_public_key(key.encode(),
                                                       backend=default_backend())
        return public_key
