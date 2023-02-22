import hashlib
import tarfile
from io import BytesIO

import docker

# statically define files and directories which shall be exempt from hash file comparison
_DEFAULT_PATH_EXCEPTIONS = [
    b"opt/pht_results",
    b"opt/pht_train",
    b"opt/train_config.json",
    b"opt/user_sym_key.key",
    b"opt/.wh.",
]


def _default_docker_client():
    try:
        client = docker.from_env()

    except Exception:
        client = docker.DockerClient(base_url="unix://var/run/docker.sock")

    return client


def validate_train_image(
    master_image_name: str,
    train_image_name: str,
    path_exceptions=_DEFAULT_PATH_EXCEPTIONS,
    docker_client=_default_docker_client(),
):
    """
    Validates a train image against an official master image
    :param master_image_name: string identifier of the master docker image to validate against
    :param train_image_name: string identifier of the docker image defining a train
    :param path_exceptions: list of byte strings containing paths that shall be exempt from file system comparison
    :param docker_client: docker client able to apply for the master and train docker image
    :return:
    """

    # extract docker images by name through client
    master_image = docker_client.images.get(master_image_name)
    train_image = docker_client.images.get(train_image_name)

    # check if history entries indicate that train image stems from master image
    if _do_history_test(master_image, train_image):
        # extract file system hashes
        master_hashes = _get_file_hashes(master_image, path_exceptions)
        train_hashes = _get_file_hashes(train_image, path_exceptions)

        # if comparison of hashed files systems turns out as False raise ValueError
        if not dict(sorted(master_hashes.items())) == dict(
            sorted(train_hashes.items())
        ):
            raise ValueError(
                "File system of train image could not be validated. Hashed file system comparison "
                "implicated error during validation."
            )
    # if train images does not stem from master image raise Value Error
    else:
        raise ValueError(
            "File system of train image could not be validated. History entries implicated error during "
            "validation."
        )


def _do_history_test(master_image, train_image) -> bool:
    """
    Compare history entries between images, to ensure that the given train image is a successor to the master image.
    :param master_image: master image object whose history entries will be used as base
    :param train_image: train image object whose history entries should contain the master image history entry's
    :return: boolean fo whether all master image history entries are also in the train image history
    """
    # Extract history entry ids
    master_img_entry_ids = [
        {key: entry[key] for key in ["Created", "CreatedBy", "Size"]}
        for entry in master_image.history()
    ]
    train_img_entry_ids = [
        {key: entry[key] for key in ["Created", "CreatedBy", "Size"]}
        for entry in train_image.history()
    ]

    # Check whether all entry ids of the master image history are also in the train image's
    is_history_test_true = all(
        [entry_dict in train_img_entry_ids for entry_dict in master_img_entry_ids]
    )
    return is_history_test_true


def _get_file_hashes(
    docker_image, path_exceptions: list[bytes]
) -> dict[bytes : list[str]]:
    """
    Extracts file system of docker image and returns dictionary with byte paths as keys and list of hashed file
    contents from layers
    :param docker_image: docker image object whose file system is to be extracted and hashed
    :param path_exceptions: list of byte strings for paths that, if they start with either of them, will be excluded
                            from the returned hashed file system
    :return: dictionary containing the hashed file system with byte paths as keys and list of associated
             hashed file contents
    """
    # init dict which will collected hashes and be returned
    image_hashes = {}

    # extract file system form images as chunks collected into a bytearray
    bytes_arr = bytearray()
    for chunk in docker_image.save():
        bytes_arr.extend(chunk)

    # unzip chunk.tar from buffer
    with tarfile.open(fileobj=BytesIO(bytes_arr)) as outer:
        # isolate and extract layer.tar files
        layers_tars = [n for n in outer.getnames() if n.endswith("/layer.tar")]
        for i, layer_tar in enumerate(layers_tars):
            layer_file = outer.extractfile(layer_tar)
            if layer_file is None:
                continue

            # unzip layer.tar files
            with tarfile.open(fileobj=layer_file, encoding="utf-8") as layer:
                # collect paths in file system as keys and file contents as items in dictionary, if path does not start
                # with any of the excepted paths
                paths_in_layer = {
                    x.encode("utf-8"): layer.getmember(x)
                    for x in layer.getnames()
                    if all(
                        [not x.encode("utf-8").startswith(y) for y in path_exceptions]
                    )
                }

                # collect hashes of file contents into lists using the paths as keys for all layer.tar files
                for path, content in paths_in_layer.items():
                    # path leads to anything but a file, set list with empty string (e.g. It is there. And that's it.)
                    if not content.isfile():
                        image_hashes[path] = [""]
                    else:
                        f = layer.extractfile(content)
                        h = hashlib.sha256()
                        h.update(f.read())
                        if path in image_hashes.keys():
                            image_hashes[path].append(h.hexdigest())
                            image_hashes[path] = sorted(image_hashes[path])
                        else:
                            image_hashes[path] = [h.hexdigest()]
    return image_hashes
