from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from train_lib.security.protocol import SecurityProtocol
import os
from train_lib.security.hashing import hash_immutable_files


def generate_user_key_pair():
    user_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("user_private_key.pem", "wb") as f:
        f.write(pem)
    user_public_key = user_private_key.public_key()
    public_pem = user_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("user_public_key.pem", "wb") as f:
        f.write(public_pem)


def sign(rsa_private_key: rsa.RSAPrivateKey, digest: bytes):
    sig = rsa_private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH),
        utils.Prehashed(hashes.SHA512())
    )
    return sig.hex()


if __name__ == '__main__':
    # generate_user_key_pair()
    # with open("../../airflow-rest-api/Stations Keys/S_1_sk.pem", "rb") as pk:
    #     private_key = serialization.load_pem_private_key(pk.read(), password=None,
    #                                                      backend=default_backend())
    #     print(private_key)
    # Generate simulated values for hashes
    # session_id = bytes.fromhex("da5b1de1025815cf4f2f7adfd6009ef5e516db6b15c2e895833b761ade7a3c1be0dd2e46aac70fb88f557963f628d9c2ece3e6597dcd50788cc9fde3d10b8a3b")
    # files = list()
    # print("parsing files")
    # for (dir_path, dir_names, file_names) in os.walk("../scripts"):
    #     files += [os.path.join(dir_path, file) for file in file_names]
    # # hash = hash_immutable_files(files, "1", session_id)

    train_hash = bytes.fromhex(
        "c57063b81eb4292df94dc329477495f43576fc093e88d2c9b9e32014555d4c6861a19cbee720799df7dedcf33aa2d696acf1668a5275e2e18a40134f1c34124d")
    print("Hash: ", train_hash.hex())
    with open("./user_private_key.pem", "rb") as pk:
        private_key = serialization.load_pem_private_key(pk.read(), password=None, backend=default_backend())
        sig = private_key.sign(
            train_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH),
            utils.Prehashed(hashes.SHA512())
        )
        print("Signature: ", sig.hex())
    # with open("./demo_key.pem", "rb") as pk:
    #     private_key = serialization.load_pem_private_key(pk.read(), password="start123".encode(), backend=default_backend())
    #     sig = private_key.sign(
    #         train_hash,
    #         padding.PSS(
    #             mgf=padding.MGF1(hashes.SHA512()),
    #             salt_length=padding.PSS.MAX_LENGTH),
    #         utils.Prehashed(hashes.SHA512())
    #     )
    #     print("Demo Signature: ", sig.hex())
    with open("./user_public_key.pem", "rb") as pk:
        pk_pem = pk.read().hex()
        public_key: rsa.RSAPublicKey = serialization.load_pem_public_key(bytes.fromhex(pk_pem),
                                                                         backend=default_backend())
        print("Public Key:", pk_pem)

    public_key.verify(
        sig,
        train_hash,
                      padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
                      utils.Prehashed(hashes.SHA512()))

    with open("./S_2_sk.pem", "rb") as station_sk:
        private_key = serialization.load_pem_private_key(station_sk.read(), password=None,
                                                         backend=default_backend())

        print(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1).hex())
