import random

import pytest
from train_lib.security import primes, homomorphic_addition


def test_primes():
    # small primes
    assert Primes.is_probably_prime(17)
    assert Primes.is_probably_prime(1)

    assert not Primes.is_probably_prime(20)

    assert Primes.is_probably_prime(46861, k=100)


def test_generate_prime():
    prime = Primes.generate_prime(128)
    assert Primes.is_probably_prime(prime)

    prime_with_k = Primes.generate_prime(128, 20)

    assert Primes.is_probably_prime(prime_with_k)


def test_create_public_key():
    n = random.randint(100, 1000)
    public_key = HomomorphicAddition.PublicKey(n)
    assert public_key

    repr_string = f"<PublicKey: {n}>"

    assert str(public_key) == repr_string


def test_modulo_inverse():
    inv_mod_1 = HomomorphicAddition.invmod(3, 11)

    assert inv_mod_1 == 4

    with pytest.raises(ValueError):
        HomomorphicAddition.invmod(0, 21312)

    with pytest.raises(ValueError):
        inv_mod_2 = HomomorphicAddition.invmod(14, 12)


def test_homomorphic_encrypt():
    n = 327
    public_key = HomomorphicAddition.PublicKey(n)

    encrypted = HomomorphicAddition.encrypt(public_key, n)

    assert encrypted

    assert encrypted != n


def test_encrypted_addition():
    n = random.randint(5000, 3213123)
    public_key = HomomorphicAddition.PublicKey(n)
    a = 32
    b = 17
    encrypted_a = HomomorphicAddition.encrypt(public_key, a)
    encrypted_b = HomomorphicAddition.encrypt(public_key, b)

    encrypted_add = HomomorphicAddition.enc_add(public_key, encrypted_a, encrypted_b)

    assert encrypted_add


def test_secure_addition():
    test_n = random.randint(1000, 100000)
    public_key = HomomorphicAddition.PublicKey(test_n)
    a = 32
    b = 64
    encrypted_a = HomomorphicAddition.encrypt(public_key, a)
    encrypted_b = HomomorphicAddition.encrypt(public_key, b)

    encrypted_add = HomomorphicAddition.enc_add(public_key, encrypted_a, encrypted_b)

    assert encrypted_add

    with pytest.raises(ValueError):
        added = HomomorphicAddition.secure_addition(a, 0, None)

    added = HomomorphicAddition.secure_addition(a, b, test_n)

    assert added

    added_2 = HomomorphicAddition.secure_addition(a, b, test_n)

    added_no_prev = HomomorphicAddition.secure_addition(a, None, test_n)

    assert added_no_prev

