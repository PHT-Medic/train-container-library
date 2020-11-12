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
    session_id = bytes.fromhex("da5b1de1025815cf4f2f7adfd6009ef5e516db6b15c2e895833b761ade7a3c1be0dd2e46aac70fb88f557963f628d9c2ece3e6597dcd50788cc9fde3d10b8a3b")
    files = list()
    print("parsing files")
    for (dir_path, dir_names, file_names) in os.walk("../scripts"):
        files += [os.path.join(dir_path, file) for file in file_names]
    hash = hash_immutable_files(files, "1", session_id)

    hash = bytes.fromhex("de0053cd0e55607bec5c99a5a5a10897b2c50f25d5a7c5f9191e91829d2e16e3ef2256d9f275cad5a88bc819812c8aabb4b4129c7d26ce8cac2f3f9b21438854")
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
        public_key: rsa.RSAPublicKey = serialization.load_pem_public_key(bytes.fromhex("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b4341514541304d742f447737795059486e33527848722f48360a376e4b66636b466d4262447a316e2f7a6b735970696d656f727a326a49484f30317344613333526369734c4431483955645172524a76517878613654744d586b0a636f63324d514c344150614e3939582b39797562464150677854397853484e676d306a4c54746a4c524e6878515573654b75454f524e38366e696e354446504f0a44516371517171324b71434a7349526b656145636f37673838652b3945434f6e48412f37457577767956344a777730346d772f667449442f66446f43555330710a41506a6d2b544e5a4373764a706c376949556678424d546e47566656372f4c4b48554478637975446a64357966524d6c433776414837476a6e55527170464f4e0a4e654653444162696358386576313332366d38383057646e72364f6b796d532b4f6c4d562f4334636a6a47374435755a4d6539516f4b4d64325472324b6d64390a50514944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a"),
                                                                         backend=default_backend())
        print("Public Key:", pk_pem)

    public_key.verify(sig, hash, padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                              utils.Prehashed(hashes.SHA512()))


