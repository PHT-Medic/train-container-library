import os
from io import BytesIO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from train_lib.security.train_config import TrainConfig

SYMMETRIC_KEY_LENGTH = 256


class KeyManager:
    """
    Class that creates, stores and if necessary updates all relevant keys for symmetric and asymmetric encryption
    """

    def __init__(self, train_config: TrainConfig):
        """
        Initialize a KeyManager instance that handles security relevant values based on a train configuration

        :param train_config: either a path to a json file storing the configuration values or a dictionary with these
            values
        """
        self.config = train_config

    def save_config(self, path=None, binary_file=False):
        """
        Store the updated config file as a json at the same location

        :return:
        :rtype:
        """
        if binary_file:
            return BytesIO(self.config.json(indent=2, by_alias=True).encode("utf-8"))

        elif path:
            with open(path, "w") as f:
                f.write(self.config.json(indent=2, by_alias=True))
        else:
            raise ValueError("No path or binary file specified for saving the keyfile")

    @staticmethod
    def generate_symmetric_key():
        """
        Create a symmetric fernet key for encrypting sensitive files
        :return:
        """
        key = AESCCM.generate_key(SYMMETRIC_KEY_LENGTH)
        return key

    def decrypt_symmetric_key(
        self,
        encrypted_key: str,
        private_key_path: str,
        private_key_password: str = None,
    ) -> bytes:
        """
        Decrypts the symmetric key using a stored private key
        :arg encrypted_key: the encrypted symmetric key to decrypt in hex format
        :arg private_key_path: path to the private key file
        :arg private_key_password: optional password to decrypt the private key
        :return: symmetric fernet key used to encrypt and decrypt files
        """
        private_key = self.load_private_key(
            key_path=private_key_path, password=private_key_password
        )

        symmetric_key = private_key.decrypt(
            ciphertext=bytes.fromhex(encrypted_key),
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
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

    def encrypt_symmetric_key(self, sym_key: bytes, public_key_hex: str) -> str:
        """
        Encrypt the symmetric key with all public keys provided in the train configuration file

        :param sym_key: byte object containing the the symmetric key used to encrypt the mutable files
        :return: dictionary containing the symmetric key encrypted with all available public keys, keys are the station
        ids and values are the symmetric key encrypted with the RSA public key associated with the station id

        :rtype: str
        """

        public_key = self.load_public_key(public_key_hex)

        encrypted_key = public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        )
        return encrypted_key.hex()

    def _rsa_pk_encrypt(self, val, public_key):
        encrypted = public_key.encrypt(
            val,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        )
        return encrypted.hex()

    @staticmethod
    def load_private_key(
        env_key: str = None, key_path: str = None, password: str = None
    ) -> RSAPrivateKey:
        """
        Loads the private key from the path provided in the environment variables of the currently
        running image
        :param key_path: path to a file containing the private key
        :param env_key: environment variable containing a hex string representing the station private key
        :return: a private key object either rsa or ec
        """

        if env_key and key_path:
            raise ValueError(
                f"Multiple private Key locations specified: \n {env_key} \n {key_path}"
            )
        # Load key from hex string stored in environment variable
        if env_key:
            private_key = serialization.load_pem_private_key(
                bytes.fromhex(os.getenv(env_key)),
                password=None,
                backend=default_backend(),
            )
        # Load key from file
        elif key_path:
            with open(key_path, "rb") as sk_f:
                private_key = serialization.load_pem_private_key(
                    sk_f.read(),
                    password=password.encode() if password else None,
                    backend=default_backend(),
                )
        else:
            raise ValueError(
                "No environment variable or file containing a private key specified"
            )

        return private_key

    @staticmethod
    def load_public_key(key: str):
        """
        Loads a public key
        :param key: string representation of a public key
        :return: public key object for asymmetric encryption
        """
        public_key = serialization.load_pem_public_key(
            bytes.fromhex(key), backend=default_backend()
        )
        return public_key
