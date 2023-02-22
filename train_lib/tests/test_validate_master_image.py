import tarfile
import time
from io import BytesIO

import pytest

from train_lib.docker_util.validate_master_image import validate_train_image


def test_validate_master_image(master_image, train_image, docker_client):
    print("\nComparison: master_img vs. train_img (SUCCESS)", end="")
    _file_system_change_test(master_image, train_image, docker_client, "none", True)

    docker_client.images.pull("hello-world")
    print("\nComparison: master_img vs. random_img (FAIL)", end="")
    _file_system_change_test(master_image, "hello-world", docker_client, "none", False)

    print("\nComparison: train_img vs. master_img (FAIL)", end="")
    _file_system_change_test(train_image, master_image, docker_client, "none", False)

    for change_type in ["add", "change", "delete"]:
        for test_result in [True, False]:
            print(
                f"\nComparison: master_img vs. train_img_with_{change_type} ({'SUCCESS' if test_result else 'FAIL'})",
                end="",
            )
            _file_system_change_test(
                master_image, train_image, docker_client, change_type, test_result
            )


def _file_system_change_test(
    master_img, train_img, docker_client, change_type: str, positive_test: bool
):
    """
    Changes file system in train image according to given change type, creates a copy in the docker_client, and performs
    either positive or negative test validation against master image.
    :param master_img: master image object for validation test
    :param train_img: train image object onto which changes will be applied
    :param docker_client: docker client associated with given docker image and where the new image will be created
    :param change_type: either "add", "change", "delete" or "none" clarifying which kind of change should be applied to
    the new train image. If no changes are applied the normal train image will be used for the validation test
    :param positive_test: boolean value determining whether a positive or negative validation test will be performed
    :return:
    """
    if change_type in ["add", "change", "delete", "none"]:
        # Define name of new train image
        new_train_img = (
            f"{train_img}_{change_type}:{'not_' if positive_test else ''}faulty"
        )

        # Determine and apply change type
        if change_type == "add":
            if positive_test:
                _add_img_file(
                    train_img, new_train_img, docker_client, "opt/pht_results/file"
                )
            else:
                _add_img_file(train_img, new_train_img, docker_client, "opt/file")
        elif change_type == "change":
            if positive_test:
                _make_change_in_img_file(
                    train_img,
                    new_train_img,
                    docker_client,
                    "opt/train_config.json",
                    ".",
                )
            else:
                _make_change_in_img_file(
                    train_img, new_train_img, docker_client, ".dockerenv", "."
                )
        elif change_type == "delete":
            if positive_test:
                _delete_img_file(
                    train_img, new_train_img, docker_client, "opt/train_config.json"
                )
            else:
                _delete_img_file(train_img, new_train_img, docker_client, ".dockerenv")
        else:
            new_train_img = train_img

        # Perform validation test
        start_t = time.time()
        if positive_test:
            validate_train_image(master_img, new_train_img, docker_client=docker_client)
            print(" -> succeeds")
        else:
            with pytest.raises(ValueError):
                validate_train_image(
                    master_img, new_train_img, docker_client=docker_client
                )
            print(" -> fails")
        print(f"{time.time() - start_t:.2f}s")
    else:
        raise ValueError("File system change test was given an invalid change type.")


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
