import tarfile
import time
from io import BytesIO

import pytest

from train_lib.docker_util.validate_master_image import validate_train_image


def test_validate_master_image(master_image, train_image, docker_client):
    start_t = time.time()
    print("\nComparison: master_image vs. train_image (Success)", end="")
    validate_train_image(master_image, train_image, docker_client=docker_client)
    print(" -> succeeds")
    print(f"{time.time() - start_t:.2f}s")

    docker_client.images.pull("hello-world")
    start_t = time.time()
    print("\nComparison: master_image vs. random_image (Fail)", end="")
    with pytest.raises(ValueError):
        validate_train_image(master_image, "hello-world", docker_client=docker_client)
    print(" -> fails")
    print(f"{time.time() - start_t:.2f}s")

    start_t = time.time()
    print("\nComparison: train_image vs. master_image (FAIL)", end="")
    with pytest.raises(ValueError):
        validate_train_image(train_image, master_image, docker_client=docker_client)
    print(" -> fails")
    print(f"{time.time() - start_t:.2f}s")

    new_train_image = f"{train_image}_add:faulty"
    # add archive object to new faulty image
    _add_img_file(train_image, new_train_image, docker_client, "opt/file")
    start_t = time.time()
    print("\nComparison: master_image vs. train_image_with_addition (FAIL)", end="")
    with pytest.raises(ValueError):
        validate_train_image(master_image, new_train_image, docker_client=docker_client)
    print(" -> fails")
    print(f"{time.time() - start_t:.2f}s")

    new_train_image = f"{train_image}_add:not_faulty"
    # add archive object to new not faulty image
    _add_img_file(train_image, new_train_image, docker_client, "opt/pht_results/file")
    start_t = time.time()
    print("\nComparison: master_image vs. train_image_with_addition (SUCCESS)", end="")
    validate_train_image(master_image, new_train_image, docker_client=docker_client)
    print(" -> succeeds")
    print(f"{time.time() - start_t:.2f}s")

    new_train_image = f"{train_image}_change:faulty"
    # change file in new faulty image
    _make_change_in_img_file(
        train_image, new_train_image, docker_client, ".dockerenv", "."
    )
    start_t = time.time()
    print("\nComparison: master_image vs. train_image_with_change (FAIL)", end="")
    with pytest.raises(ValueError):
        validate_train_image(master_image, new_train_image, docker_client=docker_client)
    print(" -> fails")
    print(f"{time.time() - start_t:.2f}s")

    new_train_image = f"{train_image}_change:not_faulty"
    # change file in new not faulty image
    _make_change_in_img_file(
        train_image, new_train_image, docker_client, "opt/train_config.json", "."
    )
    start_t = time.time()
    print("\nComparison: master_image vs. train_image_with_change (SUCCESS)", end="")
    validate_train_image(master_image, new_train_image, docker_client=docker_client)
    print(" -> succeeds")
    print(f"{time.time() - start_t:.2f}s")

    new_train_image = f"{train_image}_delete:faulty"
    # delete file in new faulty image
    _delete_img_file(train_image, new_train_image, docker_client, ".dockerenv")
    start_t = time.time()
    print("\nComparison: master_image vs. train_image_with_deletion (FAIL)", end="")
    with pytest.raises(ValueError):
        validate_train_image(master_image, new_train_image, docker_client=docker_client)
    print(" -> fails")
    print(f"{time.time() - start_t:.2f}s")

    new_train_image = f"{train_image}_delete:not_faulty"
    # delete file in new not faulty image
    _delete_img_file(
        train_image, new_train_image, docker_client, "opt/train_config.json"
    )
    start_t = time.time()
    print("\nComparison: master_image vs. train_image_with_deletion (SUCCESS)", end="")
    validate_train_image(master_image, new_train_image, docker_client=docker_client)
    print(" -> succeeds")
    print(f"{time.time() - start_t:.2f}s")


def _add_img_file(img: str, new_img: str, docker_client, path: str):
    """
    Adds a file to a given docker image at the specified path and creates new image from it
    :param img: identifier of the image
    :param new_img: identifier of newly created image <repository>:<tag>
    :param docker_client: docker client associated with given docker image and where the new image will be created
    :param path: filepath at which a new file will be added
    :return:
    """
    # create and commit new copy of image
    data = docker_client.containers.create(img)
    repository, tag = new_img.split(":")
    data.commit(repository=repository, tag=tag)
    data.wait()
    data.remove()

    # run copy and add file.txt at given path, overwrite new image
    data = docker_client.containers.run(new_img, detach=True)
    data.exec_run(f"touch {path}")
    data.wait()
    data.commit(repository=repository, tag=tag)
    data.wait()
    data.remove()


def _make_change_in_img_file(
    img: str, new_img: str, docker_client, path: str, added_change: str
):
    """
    Appends change to file at the specified path in given docker image and creates new image from it
    :param img:  identifier of the image
    :param new_img:  identifier of newly created image <repository>:<tag>
    :param docker_client: docker client associated with given docker image and where the new image will be created
    :param path: filepath at which the change will be appended to file
    :param added_change: string that will be appended to the specified file in the docker image
    :return:
    """

    # # create and commit new copy of image
    # data = docker_client.containers.create(img)
    # repository, tag = new_img.split(":")
    # data.commit(repository=repository, tag=tag)
    # data.wait()
    # data.remove()
    #
    # # run copy and add file.txt at given path, overwrite new image
    # data = docker_client.containers.run(new_img, detach=True)
    # data.exec_run(f"echo '{added_change}' >> {path}")
    # data.wait()
    # data.commit(repository=repository, tag=tag)
    # data.wait()
    # data.remove()

    data = docker_client.containers.create(img)
    # extract specified file
    bits, _ = data.get_archive(path, None)
    data.wait()
    bytes_arr = bytearray()
    for chunk in bits:
        bytes_arr.extend(chunk)
    # add change to raw bitstream
    bytes_arr.extend(added_change.encode("utf-8"))

    # setup old archive around new file content
    archive_obj = BytesIO()
    tar = tarfile.open(fileobj=archive_obj, mode="w")
    bytes_data = BytesIO(bytes_arr)
    info = tarfile.TarInfo(name=path.split("/")[-1])
    info.size = bytes_data.getbuffer().nbytes
    info.mtime = time.time()
    tar.addfile(info, bytes_data)
    tar.close()
    archive_obj.seek(0)

    # overwrite old archive
    data.put_archive(f"{'/'.join(path.split('/')[:-1])}/", archive_obj)
    data.wait()
    # get repository and tag for committing the container to an image
    repository, tag = new_img.split(":")
    data.commit(repository=repository, tag=tag)
    data.wait()
    data.remove()


def _delete_img_file(img: str, new_img: str, docker_client, path: str):
    """
    Deletes file at the specified path in given docker image and creates new image from it
    :param img:  identifier of the image
    :param new_img:  identifier of newly created image <repository>:<tag>
    :param docker_client: docker client associated with given docker image and where the new image will be created
    :param path: filepath of file in docker image that will be deleted
    :return:
    """
    # create and commit new copy of image
    data = docker_client.containers.create(img)
    repository, tag = new_img.split(":")
    data.commit(repository=repository, tag=tag)
    data.wait()
    data.remove()

    # run copy and remove specified file at given path, overwrite new image
    data = docker_client.containers.run(new_img, detach=True)
    data.exec_run(f"rm {path}")
    data.wait()
    data.commit(repository=repository, tag=tag)
    data.wait()
    data.remove()
