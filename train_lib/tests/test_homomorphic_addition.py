import pytest
from train_lib.security import Primes, HomomorphicAddition


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

