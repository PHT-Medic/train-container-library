from io import BytesIO
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
import json


class KeyManager:
    """
    Class that creates, stores and if necessary updates all relevant keys for symmetric and asymmetric encryption
    """

    def __init__(self, train_config: Union[str, dict]):
        """
        Initialize a KeyManager instance that handles security relevant values based on a train configuration
        
        :param train_config: either a path to a json file storing the configuration values or a dictionary with these values 
        """
        self.config_path = None
        if type(train_config) == dict:
            self.config = train_config
        else:
            self.config_path = train_config
            with open(train_config, "r") as config_file:
                self.config = json.load(config_file)

    def save_keyfile(self, path=None, binary_file=False):
        """
        Store the updated config file as a json at the same location

        :return:
        :rtype:
        """
        if binary_file:
            return BytesIO(json.dumps(self.config).encode("utf-8"))

        if not self.config_path and path:
            raise ValueError("To save the path either a path needs to given as argument or set as an instance variable")
        if path:
            self.config_path = path
        with open(self.config_path, "w") as config_file:
            json.dump(self.config, config_file, indent=2)

    def get_security_param(self, param: str):
        """
        Returns a parameter from the associated keyfile
        :param param:
        :return: value of the specified parameter
        """
        return self.config[param]

    def set_security_param(self, param: str, value):
        """
        Updates a parameter in the keyfile with the given value
        :param param: the parameter to update
        :param value: new value for param
        :return:
        """
        self.config[param] = value

    @staticmethod
    def generate_symmetric_key():
        """
        Create a symmetric fernet key for encrypting sensitive files
        :return:
        """
        return Fernet.generate_key()

    def get_sym_key(self, station_id: str, private_key_path: str = None):
        """
        Decrypts the symmetric key using a stored private key
        :arg station_id: station identifier used to load the correct public key
        :return: symmetric fernet key used to encrypt and decrypt files
        """
        if private_key_path:
            private_key = self.load_private_key(key_path=private_key_path)
        else:
            private_key = self.load_private_key(env_key="RSA_STATION_PRIVATE_KEY")
        encrypted_sym_key = self.get_security_param("encrypted_key")[station_id]
        symmetric_key = private_key.decrypt(bytes.fromhex(encrypted_sym_key),
                                            padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                algorithm=hashes.SHA512(),
                                                label=None
                                            )
                                            )
        return symmetric_key

    def generate_encrypted_keys(self, symmetric_key: bytes):
        """
        Generates a dictionary containing the symmetric key used to encrypt files, encrypted with the public keys of all
        stations on the route
        :param symmetric_key: byte object containing the symmetric key used to encrypt the mutable files
        :return: Dictionary consisting of  key = Station Id, value = Symmetric key encrypted with public key of station
        """
        enc_keys = {}
        for station, pk in self.config["rsa_public_keys"]:
            enc_keys[station] = self.encrypt_symmetric_key(symmetric_key, pk)
        return enc_keys

    def encrypt_symmetric_key(self, sym_key: bytes) -> dict:
        """
        Encrypt the symmetric key with all public keys provided in the train configuration file

        :param sym_key: byte object containing the the symmetric key used to encrypt the mutable files
        :return: dictionary containing the symmetric key encrypted with all available public keys, keys are the station
        ids and values are the symmetric key encrypted with the RSA public key associated with the station id

        :rtype: dict
        """
        encrypted_keys = {}
        for id, key in self.config["rsa_public_keys"].items():
            public_key = self.load_public_key(key)
            encrypted_key = public_key.encrypt(sym_key,
                                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                            algorithm=hashes.SHA512(),
                                                            label=None)
                                               )
            encrypted_keys[id] = encrypted_key.hex()
        return encrypted_keys

    def _rsa_pk_encrypt(self, val, public_key):
        encrypted = public_key.encrypt(val,
                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                    algorithm=hashes.SHA512(),
                                                    label=None)
                                       )
        return encrypted.hex()

    @staticmethod
    def load_private_key(env_key: str = None, key_path: str = None):
        """
        Loads the private key from the path provided provided in the environment variables of the currently
        running image
        :param key_path: path to a file containing the private key
        :param env_key: environment variable containing a hex string representing the station private key
        :return: a private key object either rsa or ec
        """

        if env_key and key_path:
            raise ValueError(f"Multiple private Key locations specified: \n {env_key} \n {key_path}")
        # Load key from hex string stored in environment variable
        if env_key:
            private_key = serialization.load_pem_private_key(bytes.fromhex(os.getenv(env_key)),
                                                             password=None,
                                                             backend=default_backend())
        # Load key from file
        elif key_path:
            with open(key_path, "rb") as sk_f:
                private_key = serialization.load_pem_private_key(sk_f.read(),
                                                                 password=None,
                                                                 backend=default_backend()
                                                                 )
        else:
            raise ValueError("No environment variable or file containing a private key specified")

        return private_key

    @staticmethod
    def load_public_key(key: str):
        """
        Loads a public key
        :param key: string representation of a public key
        :return: public key object for asymmetric encryption
        """
        public_key = serialization.load_pem_public_key(bytes.fromhex(key),
                                                       backend=default_backend())
        return public_key

