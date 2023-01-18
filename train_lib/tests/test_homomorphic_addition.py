import random

import pytest

from train_lib.security import homomorphic_addition, primes


def test_primes():
    # small primes
    assert primes.is_probably_prime(17)
    assert primes.is_probably_prime(1)

    assert not primes.is_probably_prime(20)

    assert primes.is_probably_prime(46861, k=100)


def test_generate_prime():
    prime = primes.generate_prime(128)
    assert primes.is_probably_prime(prime)

    prime_with_k = primes.generate_prime(128, 20)

    assert primes.is_probably_prime(prime_with_k)


def test_create_public_key():
    n = random.randint(100, 1000)
    public_key = homomorphic_addition.PublicKey(n, 12345)
    assert public_key

    repr_string = f"<PublicKey: {n}>"

    assert str(public_key) == repr_string


def test_modulo_inverse():
    inv_mod_1 = homomorphic_addition.invmod(3, 11)

    assert inv_mod_1 == 4

    with pytest.raises(ValueError):
        homomorphic_addition.invmod(0, 21312)

    with pytest.raises(ValueError):
        homomorphic_addition.invmod(14, 12)


def test_homomorphic_encrypt():
    n = 327
    public_key = homomorphic_addition.PublicKey(n, 12345)

    encrypted = homomorphic_addition.encrypt(public_key, n)

    assert encrypted

    assert encrypted != n


def test_encrypted_addition():
    n = random.randint(5000, 3213123)
    public_key = homomorphic_addition.PublicKey(n, 12345)
    a = 32
    b = 17
    encrypted_a = homomorphic_addition.encrypt(public_key, a)
    encrypted_b = homomorphic_addition.encrypt(public_key, b)

    encrypted_add = homomorphic_addition.enc_add(public_key, encrypted_a, encrypted_b)

    assert encrypted_add


def test_secure_addition():
    test_n = random.randint(1000, 100000)
    test_g = random.randint(1000, 100000)
    public_key = homomorphic_addition.PublicKey(test_n, test_g)
    a = 32
    b = 64
    encrypted_a = homomorphic_addition.encrypt(public_key, a)
    encrypted_b = homomorphic_addition.encrypt(public_key, b)

    encrypted_add = homomorphic_addition.enc_add(public_key, encrypted_a, encrypted_b)

    assert encrypted_add

    with pytest.raises(ValueError):
        added = homomorphic_addition.secure_addition(a, 0, test_n)

    added = homomorphic_addition.secure_addition(a, b, test_n, test_g)

    assert added

    homomorphic_addition.secure_addition(a, b, test_n, test_g)

    added_no_prev = homomorphic_addition.secure_addition(a, None, test_n, test_g)

    assert added_no_prev
