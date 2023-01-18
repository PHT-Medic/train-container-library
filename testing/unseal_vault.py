import os

import hvac
from dotenv import find_dotenv, load_dotenv


def unseal_vault(vault_url=None):
    if not vault_url:
        vault_url = os.getenv("VAULT_URL")

    client = hvac.Client(url=vault_url)

    if client.sys.is_sealed():
        for i in range(1, 4):
            unseal_key = os.getenv(f"VAULT_UNSEAL_KEY_{i}")
            response = client.sys.submit_unseal_key(key=unseal_key)
            print(response)


if __name__ == "__main__":
    load_dotenv(find_dotenv())
    unseal_vault()
