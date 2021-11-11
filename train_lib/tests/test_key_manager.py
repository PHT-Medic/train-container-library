import pytest


def test_key_manager_init():
    from train_lib.security.KeyManager import KeyManager
    km = KeyManager()
    assert km.key_list == []