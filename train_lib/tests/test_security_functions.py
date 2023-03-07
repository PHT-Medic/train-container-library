import json
import os
from io import BytesIO

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from train_lib.security.encryption import FileEncryptor
from train_lib.security.hashing import hash_immutable_files


@pytest.fixture
def config_dict_as_json():
    config_dict = {"hello": "world"}
    return json.dumps(config_dict)


def test_encryption_decryption(config_dict_as_json):
    key = AESCCM.generate_key(256)
    file_encryptor = FileEncryptor(key)

    files = [BytesIO(config_dict_as_json.encode("utf-8")), BytesIO(b"test data")]
    # Test in memory encryption
    encrypted_files = file_encryptor.encrypt_files(files, binary_files=True)
    assert encrypted_files

    decrypted_files = file_encryptor.decrypt_files(encrypted_files, binary_files=True)

    file_content_changed = False
    for i, file in enumerate(files):
        file.seek(0)
        file_content = file.read()
        decryted_content = decrypted_files[i].read()
        assert decryted_content == file_content

    assert not file_content_changed

    AESCCM.generate_key(256)
    other_file_encryptor = FileEncryptor(key)
    again_encrypted_files = other_file_encryptor.encrypt_files(
        decrypted_files, binary_files=True
    )
    other_file_encryptor.decrypt_files(again_encrypted_files, binary_files=True)


def test_encrypt_decrypt_train_files(train_files, symmetric_key, query_json):

    fe = FileEncryptor(symmetric_key)
    filenames, files = train_files
    encrypted_files = fe.encrypt_files(files, binary_files=True)
    encrypted_query = fe.encrypt_file(query_json)
    encrypted_files.append(encrypted_query)

    decrypted_files = fe.decrypt_files(encrypted_files, binary_files=True)
    decrypted_files.append(fe.decrypt_file(encrypted_query))

    for i, file in enumerate(files):
        file.seek(0)
        file_content = file.read()
        decryted_content = decrypted_files[i].read()
        assert decryted_content == file_content

    new_key = os.urandom(32)
    fe_2 = FileEncryptor(new_key)
    encrypted_files_2 = fe_2.encrypt_files(decrypted_files, binary_files=True)

    decrypted_files_2 = fe_2.decrypt_files(encrypted_files_2, binary_files=True)

    for i, file in enumerate(files):
        file.seek(0)
        file_content = file.read()
        decryted_content = decrypted_files_2[i].read()
        assert decryted_content == file_content


def test_aes_encryption():
    key = os.urandom(32)
    iv = os.urandom(16)
    file_encryptor = FileEncryptor(key=key)

    print(key.hex())
    print(iv.hex())

    data = b"longer test string over 32"

    encrypted_data = file_encryptor._encrypt_aes(data)
    decrypted_data = file_encryptor._decrypt_aes(encrypted_data)

    print(encrypted_data.hex())
    assert decrypted_data == data


def test_decryption_fails_with_wrong_key():
    key = AESCCM.generate_key(256)
    key_2 = AESCCM.generate_key(256)
    file_encryptor_1 = FileEncryptor(key)
    file_encryptor_2 = FileEncryptor(key_2)

    files = [BytesIO(b"test data")]

    encrypted_files = file_encryptor_1.encrypt_files(files, binary_files=True)
    # Should throw error when decrypting with wrong token
    with pytest.raises(ValueError):
        file_encryptor_2.decrypt_files(encrypted_files, binary_files=True)


def test_hash_immutable_files():
    files1 = [
        BytesIO(os.urandom(7328)),
        BytesIO(os.urandom(3321)),
        BytesIO(os.urandom(4251)),
    ]
    files2 = [
        BytesIO(os.urandom(328)),
        BytesIO(os.urandom(3321)),
        BytesIO(os.urandom(4251)),
    ]

    session_id = os.urandom(64)
    user_id = "test"

    same_user_id = "test"

    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(user_id.encode("utf-8"))

    for file in files1:
        digest.update(file.read())
        file.seek(0)
    digest.update(session_id)

    new_hash = digest.finalize()

    trainlib_hash = hash_immutable_files(
        files1, user_id=user_id, session_id=session_id, binary_files=True
    )

    assert new_hash == trainlib_hash

    for file in files1:
        file.seek(0)

    hash_duplicate = hash_immutable_files(
        files1, user_id=user_id, session_id=session_id, binary_files=True
    )

    assert trainlib_hash == hash_duplicate
    for file in files1:
        file.seek(0)

    hash_different_object_user_id = hash_immutable_files(
        files1, user_id=same_user_id, session_id=session_id, binary_files=True
    )

    assert trainlib_hash == hash_different_object_user_id

    for file in files1:
        file.seek(0)

    hash_files_changed = hash_immutable_files(
        files2, user_id=user_id, session_id=session_id, binary_files=True
    )
    assert trainlib_hash != hash_files_changed

    for file in files2:
        file.seek(0)

    hash_user_id_changed = hash_immutable_files(
        files1, user_id="test2", session_id=session_id, binary_files=True
    )
    assert trainlib_hash != hash_user_id_changed

    for file in files1:
        file.seek(0)
