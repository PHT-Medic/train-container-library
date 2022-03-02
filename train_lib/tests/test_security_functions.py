import pytest
import os
from io import BytesIO
import json
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from train_lib.security.hashing import hash_immutable_files, hash_results
from train_lib.security.encryption import FileEncryptor, Fernet


@pytest.fixture
def config_dict_as_json():
    config_dict = {}
    return json.dumps(config_dict)


def test_encryption_decryption(config_dict_as_json):
    file_encryptor = FileEncryptor(Fernet.generate_key())

    files = [BytesIO(config_dict_as_json.encode("utf-8"))]
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

    # TODO test file encryption with temp files


def test_decryption_fails_with_wrong_key():
    file_encryptor_1 = FileEncryptor(Fernet.generate_key())
    file_encryptor_2 = FileEncryptor(Fernet.generate_key())

    files = [BytesIO(b"test data")]

    encrypted_files = file_encryptor_1.encrypt_files(files, binary_files=True)
    # Should throw error when decrypting with wrong token
    with pytest.raises(InvalidToken):
        decrypted_files = file_encryptor_2.decrypt_files(encrypted_files, binary_files=True)


def test_hash_immutable_files():
    files1 = [BytesIO(os.urandom(7328)), BytesIO(os.urandom(3321)), BytesIO(os.urandom(4251))]
    files2 = [BytesIO(os.urandom(328)), BytesIO(os.urandom(3321)), BytesIO(os.urandom(4251))]

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

    trainlib_hash = hash_immutable_files(files1, user_id=user_id, session_id=session_id, binary_files=True)

    assert new_hash == trainlib_hash

    for file in files1:
        file.seek(0)

    hash_duplicate = hash_immutable_files(files1, user_id=user_id, session_id=session_id,
                                          binary_files=True)

    assert trainlib_hash == hash_duplicate
    for file in files1:
        file.seek(0)

    hash_different_object_user_id = hash_immutable_files(files1, user_id=same_user_id, session_id=session_id,
                                                         binary_files=True)

    assert trainlib_hash == hash_different_object_user_id

    for file in files1:
        file.seek(0)

    hash_files_changed = hash_immutable_files(files2, user_id=user_id, session_id=session_id, binary_files=True)
    assert trainlib_hash != hash_files_changed

    for file in files2:
        file.seek(0)

    hash_user_id_changed = hash_immutable_files(files1, user_id="test2", session_id=session_id,
                                                binary_files=True)
    assert trainlib_hash != hash_user_id_changed

    for file in files1:
        file.seek(0)
