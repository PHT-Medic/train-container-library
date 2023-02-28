import os
import tarfile
import time
from enum import Enum
from io import BytesIO
from tarfile import TarInfo
from typing import BinaryIO, List, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from loguru import logger

import docker
import docker.models
from train_lib.docker_util.docker_ops import (
    extract_archive,
    extract_query_json,
    files_from_archive,
    result_files_from_archive,
)
from train_lib.security.encryption import FileEncryptor
from train_lib.security.errors import ValidationError
from train_lib.security.hashing import hash_immutable_files, hash_results
from train_lib.security.key_manager import KeyManager
from train_lib.security.train_config import RouteEntry, TrainConfig


class TrainPaths(Enum):
    IMMUTABLE_DIR = "/opt/pht_train"
    RESULT_DIR = "/opt/pht_results"
    CONFIG_PATH = "/opt/train_config.json"


class SecurityProtocol:
    """
    Class that performs the security protocol outlined in the security concept

    :param station_id: PID used to identify the station and to access the correct security values inside the
        train_config.json

    :type station_id: str
    :param config: either a string containing a path to the train_config.json or a dictionary containing the values
        parsed from said json file
    :param results_dir: path to the directory containing the results
    :param train_dir: path to the directory containing the immutable files defining a train
    """

    def __init__(
        self,
        station_id: str,
        config: TrainConfig,
        results_dir: str = None,
        train_dir: str = None,
        docker_client=None,
    ):
        self.station_id = station_id

        self.config = config
        self.route_stop = next(
            (stop for stop in self.config.route if stop.station == self.station_id),
            None,
        )
        if not self.route_stop:
            raise ValidationError(f"Station {self.station_id} not found in route")
        self.key_manager = KeyManager(train_config=config)
        self.results_dir = results_dir
        self.train_dir = train_dir
        self.docker_client = docker_client
        # self.redis = redis.Redis(decode_responses=True)

    def pre_run_protocol(
        self,
        img: str = None,
        private_key_path: str = None,
        private_key_password: str = None,
        immutable_dir: str = "/opt/pht_train",
        mutable_dir: str = "/opt/pht_results",
    ):
        """
        Decrypts the files contained in the train. And performs the steps necessary to validate a train before it is
        being run

        :param img: identifier of the image from which the security relevant files will be extracted
        :param private_key_path:
        :param private_key_password:
        :param immutable_dir:
        :param mutable_dir:
        :return:
        """
        logger.info(
            f"Executing pre-run protocol at station {self.station_id} for image: {img}"
        )

        # extract and decrypt symmetric key
        key = self.key_manager.decrypt_symmetric_key(
            encrypted_key=self.route_stop.encrypted_key,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )

        # Get the content of the immutable files from the image as ByteObjects
        try:
            query = extract_query_json(img)
            logger.info("Query json extracted from image")
        except Exception as e:
            logger.warning(f"Error extracting query json from image: {e}")
            query = None

        try:
            immutable_files, file_names, query = self.extract_immutable_files(
                img=img, directory=immutable_dir, symmetric_key=key, query=query
            )
        except Exception as e:
            logger.error(f"Error extracting immutable files from image: {e}")
            raise ValidationError("Error extracting immutable files from image")

        # Check that no files have been added or removed
        # assert len(immutable_files) == len(self.config.file_list)

        self.validate_immutable_files(
            files=immutable_files,
            immutable_file_names=file_names,
            ordered_file_list=self.config.file_list,
            query=query,
        )

        # add the decrypted files back to the image
        self._add_train_files(img, immutable_files, file_names, query=query)

        if not self._is_first_station_on_route():
            self.verify_digital_signature()
            file_encryptor = FileEncryptor(key)
            # Decrypt all previously encrypted files
            mutable_files, mf_members, mf_dir = result_files_from_archive(
                extract_archive(img, mutable_dir)
            )
            decrypted_files = file_encryptor.decrypt_files(
                mutable_files, binary_files=True
            )
            self.validate_previous_results(files=decrypted_files)
            archive = self._make_results_archive(mf_dir, mf_members, decrypted_files)
            logger.info("Adding decrypted files to image")
            self._update_image(img, archive, results_path="/opt")

        logger.info("Pre-run protocol success")

    def extract_immutable_files(
        self,
        img: str,
        directory: str,
        symmetric_key: bytes = None,
        query: bytes = None,
        decrypt: bool = True,
    ):
        """
        Extracts the immutable files from the docker image and saves them to the specified directory
        :param img: docker image to extract files from
        :param directory: directory to save the files to
        :return:
        """
        logger.info("Extracting immutable files from image...")
        # Extract the files from the image
        immutable_files, file_names = files_from_archive(
            extract_archive(img, directory)
        )

        def drop_query_json(file_names, files):
            query_index = file_names.index("query.json")
            file_names.pop(query_index)
            immutable_files.pop(query_index)

        if decrypt:
            if not symmetric_key:
                raise ValueError("No symmetric key provided")
            if query:
                drop_query_json(file_names, immutable_files)
            immutable_files, query = self.decrypt_immutable_files(
                immutable_files, symmetric_key, query
            )
        else:
            if query:
                drop_query_json(file_names, immutable_files)

        return immutable_files, file_names, query

    def post_run_protocol(
        self,
        img: str = None,
        private_key_path: str = None,
        private_key_password: str = None,
    ):
        """
        Updates the necessary values in the train_config.json and encrypts the updated files after a successful train
        execution.

        :param img: identifier of the image <repository>:<tag>
        :param private_key_path: path to the private key associated with the current station and with the corresponding
            public key registered in vault under the PID chosen by the station
        :param private_key_password: optional password to decrypt the private key
        :return:
        """
        # execute the post run station side extracting the relevant files from the image
        logger.info(
            f"Executing post-run protocol at station {self.station_id} for image: {img}"
        )
        # Get the mutable files and tar archive structure
        mutable_files, mf_members, mf_dir = result_files_from_archive(
            extract_archive(img, TrainPaths.RESULT_DIR.value)
        )
        # Run the post run protocol
        encrypted_mutable_files, symmetric_key = self._post_run_outside_container(
            mutable_files, private_key_path, private_key_password
        )
        results_archive = self._make_results_archive(
            mf_dir, mf_members, encrypted_mutable_files
        )
        results_archive.seek(0)

        self.config = TrainConfig(**self.config.dict(by_alias=True))

        # get immutable files and query from image
        query = extract_query_json(img)
        immutable_files, file_names, query = self.extract_immutable_files(
            img, TrainPaths.IMMUTABLE_DIR.value, query=query, decrypt=False
        )
        # Encrypt the immutable files
        encrypted_files, query = self.encrypt_immutable_files(
            immutable_files, symmetric_key, query
        )
        # Add the encrypted files to the image
        self._add_train_files(img, encrypted_files, file_names, query)

        # update the container with the encrypted files
        self._update_image(
            img, results_archive, results_path="/opt", config_path="/opt"
        )
        logger.info(f"Successfully executed post run protocol on img: {img}")

    def _post_run_outside_container(
        self,
        mutable_files: List[BytesIO],
        private_key_path: str,
        private_key_password: str = None,
    ) -> Tuple[List[BytesIO], bytes]:
        """
        Performs the post run protocol on the mutable files contained in an image. Consisting of encrypting the
        mutable files and updateing the train_config.json. The extracted mutable files are encrypted and the
        train_config.json is updated to reflect the current state of the train.
        The changed files are written to the base image and the resulting image is tagged as latest.

        :param mutable_files: list of BytesIO objects containing the mutable files for a train
        :param private_key_path: path to private key used to sign the results
        :return:
        """
        logger.info(f"prev results hash {self.config.result_hash}")
        # Update the hash value of the mutable files
        e_d = hash_results(
            result_files=mutable_files,
            session_id=bytes.fromhex(self.config.session_id),
            binary_files=True,
        )
        self.config.result_hash = e_d.hex()
        logger.info(f"new results hash: {self.config.result_hash}")

        # Load the local private key and sign the hash of the results files
        sk = self.key_manager.load_private_key(
            key_path=private_key_path, password=private_key_password
        )
        e_d_sig = sk.sign(
            e_d,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA512()),
        )
        self.config.result_signature = e_d_sig.hex()

        # Update the digital signature of the train
        self.sign_digital_signature(sk)

        for file in mutable_files:
            file.seek(0)
        # Encrypt the files
        new_sym_key = self.key_manager.generate_symmetric_key()
        file_encryptor = FileEncryptor(new_sym_key)
        encrypted_results = file_encryptor.encrypt_files(
            mutable_files, binary_files=True
        )

        # Encrypt the new symmetric key with the available public keys and store them in the image
        self._update_symmetric_keys(new_sym_key)
        # at the last station encrypt the symmetric key using the rsa public key of the user

        return encrypted_results, new_sym_key

    def _update_image(
        self, img, results_archive: BytesIO, results_path: str, config_path: str = None
    ):
        """
        Update the base image with the encrypted results files and the updated train_config.json and tag it as
        latest
        :param img: identifier of the image <repository>:<tag>
        :param results_archive: tar archive containing the encrypted results
        :param results_path: path to write the results to
        :param config_path: path to write the updated train_config.json
        :return:
        """
        # If a config path is given update the train config inside the container
        client = self.docker_client if self.docker_client else docker.from_env()
        # base_image = img.split(":")[0] + ":" + "base"
        container = client.containers.create(img)

        if config_path:
            logger.info("Updating train config")
            config_archive = self._make_train_config_archive()
            config_archive.seek(0)
            # add_archive(img, config_archive, config_path)
            container.put_archive(config_path, config_archive)
        # add the updated results archive
        logger.info("Adding encrypted result files")
        container.put_archive(results_path, results_archive)
        # add_archive(img, results_archive, results_path)
        logger.info("Updating user key file")
        user_key = self._make_user_key()
        # add user key to opt directory
        # add_archive(img, user_key, "/opt")
        container.put_archive("/opt", user_key)
        # Tag container as latest
        self._commit_to_image(container, img)

    @staticmethod
    def _make_results_archive(archive_members, file_members, updated_files):
        """
        Creates a tar archive containing the updated results

        :param archive_members: tar directory structure of the pht_results directory
        :param file_members: the members of the archive representing actual files
        :param updated_files: updated files associated with the file_members that will be written to the archive
        :return: updated tar archive to be copied into the new image.
        """
        archive_obj = BytesIO()
        tar = tarfile.open(fileobj=archive_obj, mode="w")

        # Create directory structure
        for member in archive_members:
            if member not in file_members:
                tar.addfile(member)
        # Add the updated members to a new archive
        for i, file_member in enumerate(file_members):
            file_size = updated_files[i].getbuffer().nbytes
            updated_files[i].seek(0)
            file_member.size = file_size
            file_member.mtime = time.time()
            tar.addfile(file_member, fileobj=updated_files[i])

        # Close tarfile and reset BytesIO
        tar.close()
        archive_obj.seek(0)

        return archive_obj

    def _add_train_files(
        self, img: str, train_files: List[BytesIO], file_names: List[str], query=None
    ):
        """
        Create in memory tar archive containing the train files and add it to the image
        :param img: identifier of the image <repository>:<tag>
        :param train_files: list of train files
        :param file_names: names of the train files
        :return:
        """

        logger.info("Adding train files...", nl=False)

        if query:
            if isinstance(query, bytes):
                query = BytesIO(query)
            elif isinstance(query, BytesIO):
                pass
            else:
                raise TypeError("Query must be of type bytes or BytesIO")
        train_file_archive = self._make_train_files_archive(
            train_files=train_files, file_names=file_names, query=query
        )

        client = self.docker_client if self.docker_client else docker.from_env()
        container = client.containers.create(img)
        train_file_archive.seek(0)
        container.put_archive("/opt", train_file_archive)
        container.wait()
        self._commit_to_image(container, img)
        logger.info("Done")

    def _commit_to_image(self, container, img):
        """
        Commit the container to the image and remove the container
        :param container:
        :param img:
        :return:
        """
        # Tag container as latest
        img_split = img.split(":")
        if len(img_split) == 1:
            repo = img_split[0]
            tag = "latest"
        elif len(img_split) == 2:
            repo, tag = img_split
        else:
            repo = ":".join(img_split[:-1])
            tag = img_split[-1]
        container.commit(repository=repo, tag=tag)
        container.wait()
        container.remove()

    @staticmethod
    def _make_train_files_archive(
        train_files: List[BytesIO], file_names: List[str], query: BytesIO = None
    ) -> BytesIO:
        """
        Create a tar archive containing the train files and the query file
        :param train_files: list of in memory file objects defining the algorithm of the train
        :param file_names: names of the train files
        :param query: optional query file
        :return: Tar archive containing the train files and the query file
        """
        archive_obj = BytesIO()
        tar = tarfile.open(fileobj=archive_obj, mode="w")

        if query:
            query.seek(0)
            info = TarInfo(name="pht_train/query.json")
            info.size = query.getbuffer().nbytes
            info.mtime = time.time()
            tar.addfile(info, query)
        for i, train_file in enumerate(train_files):
            train_file.seek(0)
            info = TarInfo(name=f"pht_train/{file_names[i]}")
            info.size = train_file.getbuffer().nbytes
            info.mtime = time.time()
            # add config data and reset the archive
            tar.addfile(info, train_file)
        tar.close()
        archive_obj.seek(0)

        return archive_obj

    def _make_train_config_archive(self) -> BytesIO:
        """
        Create in memory tar archive containing the train configuration json file
        :return:
        """
        archive_obj = BytesIO()
        tar = tarfile.open(fileobj=archive_obj, mode="w")
        data = BytesIO(self.config.json(indent=2, by_alias=True).encode("utf-8"))

        # Create TarInfo Object based on the data
        info = TarInfo(name="train_config.json")
        info.size = data.getbuffer().nbytes
        info.mtime = time.time()
        # add config data and reset the archive
        tar.addfile(info, data)
        tar.close()
        archive_obj.seek(0)
        return archive_obj

    def _make_user_key(self):
        archive_obj = BytesIO()
        tar = tarfile.open(fileobj=archive_obj, mode="w")
        # Extract user key from config and convert it to bytesio
        data = BytesIO(bytes.fromhex(self.config.creator.encrypted_key))
        info = TarInfo(name="user_sym_key.key")
        info.size = data.getbuffer().nbytes
        info.mtime = time.time()
        tar.addfile(info, data)
        tar.close()
        archive_obj.seek(0)
        return archive_obj

    def validate_immutable_files(
        self,
        train_dir: str = None,
        files: list = None,
        ordered_file_list: List[str] = None,
        immutable_file_names: List[str] = None,
        query: bytes = None,
    ):
        """
        Checks if the hash of the immutable files is the same as the one stored at the creation of the train

        :raises ValidationError: when the files to be executed do not match the agreed upon files

        :return:
        """
        # check the signature of the stored hash value using ec signature verifying that it is created by the user
        user_pk = self.key_manager.load_public_key(self.config.creator.rsa_public_key)
        e_h = bytes.fromhex(self.config.hash)
        e_h_sig = bytes.fromhex(self.config.signature)
        # now check before the run that no immutable files have changed, based on stored hash
        if train_dir:
            immutable_files = self._parse_files(train_dir)
            immutable_files = [
                str(file)
                for file in immutable_files
                if "train_config.json" not in str(file)
            ]

            current_hash = hash_immutable_files(
                immutable_files=immutable_files,
                user_id=str(self.config.creator.id),
                session_id=bytes.fromhex(self.config.session_id),
                query=query,
            )
        elif files:
            current_hash = hash_immutable_files(
                immutable_files=files,
                user_id=str(self.config.creator.id),
                session_id=bytes.fromhex(self.config.session_id),
                binary_files=True,
                ordered_file_list=ordered_file_list,
                immutable_file_names=immutable_file_names,
                query=query,
            )
        else:
            raise ValueError("Either train_dir or files must be provided")

        logger.info(f"Stored hash: {e_h}")
        logger.info(f"Current hash: {current_hash}")
        if e_h != current_hash:
            raise ValidationError("Immutable Files have changed")
        # Verify that the hash value corresponds with the signature
        user_pk.verify(e_h_sig, current_hash, padding.PKCS1v15(), hashes.SHA512())
        # validate the build signature to ensure no tampering has occurred
        self.validate_build_signature(current_hash.hex())

    def validate_previous_results(self, files: List[BinaryIO]):
        """
        Verify that the results from the execution of the previous station did not change, by hashing the stored results
        from the previous station and comparing it with the decrypted stored hash from the previous station
        """
        # Get public key of the previous station
        prev_station = self._get_previous_station()
        station_public_key = self.key_manager.load_public_key(
            prev_station.rsa_public_key
        )
        results_hash = hash_results(
            files, session_id=bytes.fromhex(self.config.session_id), binary_files=True
        )
        if results_hash != bytes.fromhex(self.config.result_hash):
            raise ValidationError("Previous results have changed")
        try:

            station_public_key.verify(
                signature=bytes.fromhex(self.config.result_signature),
                data=results_hash,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                algorithm=utils.Prehashed(hashes.SHA512()),
            )
        except Exception as e:
            logger.error(f"Error verifying previous results: {e}")
            raise ValidationError("Error validating previous results signature")

    def sign_digital_signature(self, sk: RSAPrivateKey):
        """
        Update the digital signature of the train after successful execution of the train.
        If there is no previous signature present creates a signature based on the session id, otherwise the
        signature of the previous station is loaded, signed using the current stations private key and appended to
        the list of signatures stored in the train.

        :param sk: private key of the currently running station
        """
        # ds = self.key_manager.get_security_param("digital_signature")
        # sort the route by index for signing the signature in order
        sorted_route = sorted(self.config.route, key=lambda x: x.index)

        hasher = hashes.Hash(hashes.SHA512(), default_backend())
        # use the session id when first station on route
        if self.route_stop.index == 0:
            hasher.update(bytes.fromhex(self.config.session_id))
        else:
            for stop in sorted_route:
                if stop.index < self.route_stop.index:
                    hasher.update(bytes.fromhex(stop.signature.digest))
                else:
                    break

        hasher.update(bytes.fromhex(self.config.result_hash))
        digest = hasher.finalize()
        sig = sk.sign(
            data=digest,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=utils.Prehashed(hashes.SHA512()),
        )
        self.route_stop.signature = {"signature": sig.hex(), "digest": digest.hex()}

        sorted_route[self.route_stop.index] = self.route_stop

        self.config.route = sorted_route

    def verify_digital_signature(self):
        """
        Verifies the digital signature of the train by iterating over the list of signatures and verifying each one
        using the correct public key stored in the train configuration json

        :raise: InvalidSignatureError if any of the signed values can not be validated using the provided public keys

        """

        sorted_route = sorted(self.config.route, key=lambda x: x.index)

        for stop in sorted_route:
            if stop.index >= self.route_stop.index:
                break
            else:

                if not stop.signature:
                    error = ValidationError(
                        f"Missing digital signature for previous stop {stop}. \n"
                        f" While currently at {self.route_stop}"
                    )
                    logger.error(error)
                    raise error
                pk = self.key_manager.load_public_key(stop.rsa_public_key)
                pk.verify(
                    signature=bytes.fromhex(stop.signature.signature),
                    data=bytes.fromhex(stop.signature.digest),
                    padding=padding.PSS(
                        mgf=padding.MGF1(hashes.SHA512()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    algorithm=utils.Prehashed(hashes.SHA512()),
                )

    def validate_build_signature(self, immutable_file_hash: str):
        """
        Validate that the hash of the locally available file corresponds to initial hash provided by the builder
        in combination with the user signature
        :param immutable_file_hash:
        :return:
        """

        logger.info("Validating build signature... ", nl=False)
        builder_pk = self.key_manager.load_public_key(self.config.build.rsa_public_key)

        content = immutable_file_hash + self.config.signature
        try:
            builder_pk.verify(
                bytes.fromhex(self.config.build.signature),
                bytes.fromhex(content),
                padding.PKCS1v15(),
                hashes.SHA512(),
            )
            logger.info("OK")

        except Exception as e:

            logger.error(f"Error\n {e}")
            raise ValidationError("Error validating build signature.")

    def encrypt_immutable_files(
        self, files: List[BytesIO], symmetric_key: bytes, query=None
    ):
        """
        Encrypts the immutable files
        :param files: dictionary containing the files to encrypt
        :param symmetric_key: symmetric key to encrypt the files with
        :return:
        """
        logger.info("Encrypting immutable files...")
        file_encryptor = FileEncryptor(symmetric_key)
        encrypted_files = file_encryptor.encrypt_files(files, binary_files=True)
        if query:
            encrypted_query = file_encryptor.encrypt(query)
            return encrypted_files, encrypted_query
        return encrypted_files, None

    def decrypt_immutable_files(
        self, immutable_files: List[BinaryIO], symmetric_key: bytes, query: bytes = None
    ) -> Union[Tuple[List[BytesIO], bytes], Tuple[List[BytesIO], None]]:
        """
        Decrypts the immutable files of the train using the private key of the currently running station
        :param query: optional bytes for query json
        :param symmetric_key:
        :param immutable_files: list of binary files to decrypt
        :return: list of decrypted files
        """

        fe = FileEncryptor(key=symmetric_key)
        decrypted_files = fe.decrypt_files(immutable_files, binary_files=True)
        if query:
            decrypted_query = fe.decrypt(query)
            return decrypted_files, decrypted_query
        return decrypted_files, None

    def _is_first_station_on_route(self) -> bool:
        """
        Returns true if current station is the first station on the route
        :return:
        """
        # Check if there are previous results if not station is first station on route
        return self.config.result_hash is None

    def _get_previous_station(self) -> RouteEntry:
        for stop in self.config.route:
            if stop.index == self.route_stop.index - 1:
                return stop

    @staticmethod
    def _parse_files(target_dir):
        """
        Parses the exported files from a container and sorts them into relevant categories
        :param target_dir: directory in which to find all files
        :return: Tuple consisting of lists of paths for the different file types
        """
        files = list()
        logger.info("Detecting files...")
        for (dir_path, dir_names, file_names) in os.walk(target_dir):
            files += [os.path.join(dir_path, file) for file in file_names]
        logger.info(f"Found {len(files)} Files")
        return files

    def _update_symmetric_keys(self, new_sym_key: bytes):
        """
        Updates the symmetric key for the train creator and all stations on the route
        :param new_sym_key:
        :return:
        """
        for i, station in enumerate(self.config.route):
            station.encrypted_key = self.key_manager.encrypt_symmetric_key(
                new_sym_key, station.rsa_public_key
            )
            self.config.route[i] = station

        self.config.creator.encrypted_key = self.key_manager.encrypt_symmetric_key(
            new_sym_key, self.config.creator.rsa_public_key
        )
