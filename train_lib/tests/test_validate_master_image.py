import time

import pytest

from train_lib.docker_util.validate_master_image import validate_train_image


def test_validate_master_image(master_image, train_image, docker_client):
    start_t = time.time()
    print("\nComparison: master_image vs. train_image")
    validate_train_image(master_image, train_image, docker_client=docker_client)
    print(f"{time.time() - start_t:.2f}s")

    docker_client.images.pull("hello-world")
    start_t = time.time()
    print("\nComparison: master_image vs. random_image")
    with pytest.raises(ValueError):
        validate_train_image(master_image, "hello-world", docker_client=docker_client)
    print(f"{time.time() - start_t:.2f}s")

    start_t = time.time()
    print("\nComparison: train_image vs. master_image")
    with pytest.raises(ValueError):
        validate_train_image(train_image, master_image, docker_client=docker_client)
    print(f"{time.time() - start_t:.2f}s")
