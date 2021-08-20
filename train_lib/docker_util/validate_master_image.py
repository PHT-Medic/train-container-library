import subprocess
from typing import List, Tuple



def validate_train_image(train_img: str, master_image: str):
    """
    Validates a train image against an official master image
    :param train_img: identifier of the docker image defining a train
    :param master_image: identifier of the master docker image to validate against
    :return:
    """

    status, message = _compare_image_file_system(master_image, train_img)
    print(message)
    if status != 0:
        raise ValueError(f"File system could not be validated. \n {message}")


def _compare_image_file_system(master_image_name: str, train_image_name: str):
    """
    Compares the full file systems of the master image against, any added, changed or deleted files will be detected
    and if any changes are detected outside of the PHT specific directories will be considered invalid and raise an
    error.
    Uses the container-diff tool from google: https://github.com/GoogleContainerTools/container-diff

    :param master_image_name:
    :param train_image_name:
    :return:
    """

    container_diff_args = ["container-diff", "diff", f"daemon://{master_image_name}",
                           f"daemon://{train_image_name}", "--type=file"]
    output = subprocess.run(container_diff_args, capture_output=True)
    file_system_diff = output.stdout.decode().splitlines()
    valid, msg = _validate_file_system_changes(file_system_diff)
    if valid:
        return 0, "No file system anomalies detected"
    else:
        return 1, "Invalid file system changes detected, files can only be added into " \
                  f"/opt/pht_train, but found {msg}"


def _validate_file_system_changes(file_system_diff: List[str]) -> Tuple[bool, str]:
    """
    Validate the file system changes found by the container-diff tools.
    Checks if files have been added at the right location and whether files have been deleted or changed compared
    to the master image

    :param file_system_diff: output generated by the container-diff tool analysing the file system changes between
    two images

    :return: whether the detected changes to the file system are valid
    """
    add_ind = None
    deleted_ind = None
    changed_ind = None
    valid = False
    for ind, content in enumerate(file_system_diff):
        if "These entries have been added" in content:
            add_ind = ind
        elif "These entries have been deleted" in content:
            deleted_ind = ind
        elif "These entries have been changed" in content:
            changed_ind = ind
    # Find the files added to the image file system and make sure they are located exclusively under /opt/pht_train
    if len(file_system_diff[add_ind: deleted_ind]) > 2:
        print("Added files detected.")
        valid = True
        invalid_files = []
        for file in file_system_diff[add_ind + 2: deleted_ind]:
            valid_file, file = _validate_added_file(file)
            if not valid_file:
                valid = False
                invalid_files.append(file)
        invalid_file_string = "\n".join(invalid_files)
        if not valid:
            return False, f"Incorrectly added files:\n{invalid_file_string} "
    # If the length of the deleted files section is greater than two, files have been deleted from the master image
    # -> image invalid
    if len(file_system_diff[deleted_ind: changed_ind]) > 2:
        print("Deleted Files detected")
        valid = False
    # If the length of the deleted files section is greater than two, files have been changed from the master image
    # -> image invalid
    if len(file_system_diff[changed_ind:]) > 2:
        print("Changed files detected")
        valid = False
    if valid:
        print("Validation success!")

    return valid, "Successfully verified file system"


def _validate_added_file(file: str) -> Tuple[bool, str]:
    """
    Checks whether an added file detected by container-diff is located under /opt/pht_train.

    :param file: line of output generated by container diff containing info on the added file
    :return: whether the file is correctly located or not
    """
    path = file.split(" ")[0]
    valid = False

    print(f"Validate called with file: {file}")
    if not file:
        return True, path


    if len(path) > 1:
        path_dir = path.split("/")[1:]

        if path_dir[0] == "opt":

            if path_dir[1] == "pht_results":
                valid = True
            if path_dir[1] == "pht_train":
                valid = True

            if path_dir[1] == "train_config.json":
                valid = True
    if not valid:
        print(f"Invalid file detected: {path}")

    return valid, path
