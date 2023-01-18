import json
import os

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import find_dotenv, load_dotenv

TEST_STATIONS = ["tuebingen", "aachen", "leipzig"]
KEY_DIR = os.path.abspath("./keys")


def main():
    token = os.getenv("VAULT_TOKEN")
    url = os.getenv("VAULT_URL")
    headers = {"X-Vault-Token": token}
    for station in TEST_STATIONS:
        request_url = f"{url}/v1/station_pks/{station}"
        print(request_url)
        # Generate key pairs
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Write private keys to /test/keys directory
        with open(
            os.path.join(KEY_DIR, f"station_{station}_private_key.pem"), "wb"
        ) as f:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            f.write(pem)
        # Generate public key
        public_key = private_key.public_key()
        # Encode as hex string
        public_key_hex = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex()
        print(public_key_hex)

        loaded_public_key = serialization.load_pem_public_key(
            bytes.fromhex(public_key_hex)
        )
        print(loaded_public_key)
        payload = {
            "options": {"cas": 1},
            "data": {"rsa_station_public_key": public_key_hex},
        }
        r = requests.post(request_url, headers=headers, data=json.dumps(payload))
        response = r.reason
        print(response)


if __name__ == "__main__":
    load_dotenv(find_dotenv())
    main()
