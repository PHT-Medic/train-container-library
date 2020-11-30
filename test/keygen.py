from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from train_lib.security.SecurityProtocol import SecurityProtocol
import os
from train_lib.security.Hashing import hash_immutable_files


def generate_user_key_pair():
    user_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("../test/keys/user_private_key.pem", "wb") as f:
        f.write(pem)
    user_public_key = user_private_key.public_key()
    public_pem = user_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open("../test/keys/user_public_key.pem", "wb") as f:
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

    # Generate simulated values for hashes
    # session_id = bytes.fromhex("da5b1de1025815cf4f2f7adfd6009ef5e516db6b15c2e895833b761ade7a3c1be0dd2e46aac70fb88f557963f628d9c2ece3e6597dcd50788cc9fde3d10b8a3b")
    # files = list()
    # print("parsing files")
    # for (dir_path, dir_names, file_names) in os.walk("../scripts"):
    #     files += [os.path.join(dir_path, file) for file in file_names]
    # # hash = hash_immutable_files(files, "1", session_id)


    hash = bytes.fromhex("b84e49ba9a09980af85f060d04d5dedac949620027005be786af9553a7d8967516f5de26b28dbd68b792c45fefb816ef17855d8e64fbe3a56f30eb821709da19")
    print("Hash: ", hash.hex())
    with open("../test/keys/user_private_key.pem", "rb") as pk:
        private_key = serialization.load_pem_private_key(pk.read(), password=None,
                                                         backend=default_backend())
        sig = private_key.sign(hash,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512())
                          )
        print("Signature: ", sig.hex())
    with open("../test/keys/user_public_key.pem", "rb") as pk:
        pk_pem = pk.read().hex()
        public_key: rsa.RSAPublicKey = serialization.load_pem_public_key(bytes.fromhex(pk_pem),
                                                                         backend=default_backend())
        print("Public Key:", pk_pem)

    public_key.verify(sig, hash, padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                              utils.Prehashed(hashes.SHA512()))


