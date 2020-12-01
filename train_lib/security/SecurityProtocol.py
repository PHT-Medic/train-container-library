from .KeyManager import KeyManager
from .SymmetricEncryption import FileEncryptor
from .SecurityErrors import ValidationError
from .Hashing import *
from train_lib.docker_util.docker_ops import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import utils, padding
import os
from typing import Union
import redis
import time
from tarfile import TarInfo, TarFile


class SecurityProtocol:
    """
    Class that performs the security protocol outlined in the security concept
    """

    def __init__(self, station_id: str, config: Union[str, dict], results_dir: str = None, train_dir: str = None):
        self.station_id = station_id
        self.key_manager = KeyManager(train_config=config)
        self.results_dir = results_dir
        self.train_dir = train_dir
        self.redis = redis.Redis(decode_responses=True)

    def pre_run_protocol(self, img: str = None, private_key_path: str = None, immutable_dir: str = "/opt/pht_train",
                         mutable_dir: str = "/opt/pht_results"):
        """
        Decrypts the files contained in the train. And performs the steps necessary to validate a train before it is
        being run
        :return:
        """
        print("Executing pre-run protocol...")
        # Execute the protocol with directly passed files and the instances config file
        if img and private_key_path:
            print("Extracting files from image...")
            # Get the content of the immutable files from the image as ByteObjects
            immutable_files = files_from_archive(extract_archive(img, immutable_dir))[0]
            self.validate_immutable_files(files=immutable_files)
            if not self._is_first_station_on_route():
                self.verify_digital_signature()
                file_encryptor = FileEncryptor(self.key_manager.get_sym_key(self.station_id,
                                                                            private_key_path=private_key_path))
                # TODO check this
                # Decrypt all previously encrypted files
                mutable_files, mf_members, mf_dir = files_from_archive(extract_archive(img, mutable_dir))
                decrypted_files = file_encryptor.decrypt_files(mutable_files, binary_files=True)
                self.validate_previous_results(files=decrypted_files)
                archive = self._make_results_archive(mf_dir, mf_members, decrypted_files)
                self._update_container(img, archive, results_path="/opt")
                # TODO update image

            print("Success")
            return
        # Execute the protocol parsing the files from the given train and results directories
        elif self.results_dir and self.train_dir:
            self.validate_immutable_files(self.train_dir)

            if not self._is_first_station_on_route():
                self.verify_digital_signature()

                files = self._parse_files(self.results_dir)

                file_encryptor = FileEncryptor(self.key_manager.get_sym_key(self.station_id))

                # Decrypt all previously encrypted files
                file_encryptor.decrypt_files(files)
                self.validate_previous_results()

            print("Success")
            return
        else:
            raise ValueError("Neither instance variables for  train and results directories nor the the mutable files"
                             "and immutable files arguments are set.")

    def post_run_protocol(self, img: str = None, private_key_path: str = None, mutable_dir: str = "/opt/pht_results"):
        """
        Updates the necessary values and encrypts the updated files after a successful train execution

        :param img:

        :return:
        """
        # execute the post run station side extracting the relevant files from the image
        if img and private_key_path:
            print(f"Executing post-run protocol - target image: {img} \n")
            # Get the mutable files and tar archive structure
            mutable_files, mf_members, mf_dir = files_from_archive(extract_archive(img, mutable_dir))
            # Run the post run protocol
            encrypted_mutable_files = self._post_run_outside_container(mutable_files, private_key_path)
            archive = self._make_results_archive(mf_dir, mf_members, encrypted_mutable_files)
            archive.seek(0)

            # update the container with the encrypted files
            self._update_container(img, archive, results_path="/opt", config_path="/opt")
            print(f"Successfully executed post run protocol on img: {img}")
        # execute the post run protocol running inside the docker container
        else:
            print("Executing post-run protocol: \n")
            self._post_run_in_container()

    def _post_run_outside_container(self, mutable_files: List[BytesIO], private_key_path: str) -> List[BytesIO]:
        print("prev results hash", self.key_manager.get_security_param("e_d"))
        # Update the hash value of the mutable files
        e_d = hash_results(result_files=mutable_files,
                           session_id=bytes.fromhex(self.key_manager.get_security_param("session_id")),
                           binary_files=True)
        self.key_manager.set_security_param("e_d", e_d.hex())
        print("new results hash", self.key_manager.get_security_param("e_d"))

        # Load the local private key and sign the hash of the results files
        sk = self.key_manager.load_private_key(key_path=private_key_path)
        e_d_sig = sk.sign(e_d,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512()))
        self.key_manager.set_security_param("e_d_sig", e_d_sig.hex())

        # Update the digital signature of the train
        self.sign_digital_signature(sk)

        for file in mutable_files:
            file.seek(0)
        # Encrypt the files
        new_sym_key = self.key_manager.generate_symmetric_key()
        file_encryptor = FileEncryptor(new_sym_key)
        encrypted_results = file_encryptor.encrypt_files(mutable_files, binary_files=True)

        # Encrypt the new symmetric key with the available public keys and store them in the image
        encrypted_symmetric_keys = self.key_manager.encrypt_symmetric_key(new_sym_key)
        self.key_manager.set_security_param("encrypted_key", encrypted_symmetric_keys)
        # at the last station encrypt the symmetric key using the rsa public key of the user
        # TODO does this always currently make this the permanent solution
        if self._is_last_station_on_route():
            user_public_key = self.key_manager.load_public_key(
                self.key_manager.get_security_param("rsa_user_public_key"))
            user_encrypted_sym_key = self.key_manager._rsa_pk_encrypt(new_sym_key, user_public_key)
            self.key_manager.set_security_param("user_encrypted_sym_key", user_encrypted_sym_key)

        return encrypted_results

    def _update_container(self, img, results_archive: BytesIO, results_path: str, config_path: str = None):
        # If a config path is given update the train config inside the container
        if config_path:
            config_archive = self._make_train_config_archive()
            config_archive.seek(0)
            add_archive(img, config_archive, config_path)
            config_archive.seek(0)
            print(config_archive.read())
        # add the updated results archive
        add_archive(img, results_archive, results_path)

    def _make_results_archive(self, archive_members, file_members, updated_files):
        archive_obj = BytesIO()
        tar = tarfile.open(fileobj=archive_obj, mode="w")

        # Add the updated members to a new archive
        for member in archive_members:
            if member not in file_members:
                tar.addfile(member)
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

    def _make_train_config_archive(self) -> BytesIO:
        """
        Create in memory tar archive containing the train configuration json file
        :return:
        """
        archive_obj = BytesIO()

        tar = tarfile.open(fileobj=archive_obj, mode="w")

        data = self.key_manager.save_keyfile(binary_file=True)

        # Create TarInfo Object based on the data
        info = TarInfo(name="train_config.json")
        info.size = data.getbuffer().nbytes
        info.mtime = time.time()

        tar.addfile(info, data)
        tar.close()
        archive_obj.seek(0)
        return archive_obj

    def _post_run_in_container(self):
        """
        Execute the post-run protocol inside of the container

        :return:
        """

        # Update the values hash and signature of the results
        files = self._parse_files(self.results_dir)
        e_d = hash_results(files, bytes.fromhex(self.key_manager.get_security_param("session_id")))
        self.key_manager.set_security_param("e_d", e_d.hex())
        sk = self.key_manager.load_private_key(env_key="RSA_STATION_PRIVATE_KEY")
        e_d_sig = sk.sign(e_d,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512()))
        self.key_manager.set_security_param("e_d_sig", e_d_sig.hex())
        # Sign the train after execution
        self.sign_digital_signature(sk)
        # Write new values to file and encrypt files with new symmetric key
        new_sym_key = self.key_manager.generate_symmetric_key()
        file_encryptor = FileEncryptor(new_sym_key)

        # Encrypt the files
        file_encryptor.encrypt_files(files)
        self.key_manager.set_security_param("encrypted_key", self.key_manager.encrypt_symmetric_key(new_sym_key))
        # at the last station encrypt the symmetric key using the rsa public key of the user
        if self._is_last_station_on_route():
            user_public_key = self.key_manager.load_public_key(
                self.key_manager.get_security_param("rsa_user_public_key"))
            user_encrypted_sym_key = self.key_manager._rsa_pk_encrypt(new_sym_key, user_public_key)
            self.key_manager.set_security_param("user_encrypted_sym_key", user_encrypted_sym_key)

        self.key_manager.save_keyfile()
        print("Success")

    def validate_immutable_files(self, train_dir: str = None, files: list = None):
        """
        Checks if the hash of the immutable files is the same as the one stored at the creation of the train

        :raises ValidationError: when the files to be executed do not match the agreed upon files

        :return:
        """
        # check the signature of the stored hash value using ec signature verifying that it is created by the user
        user_pk = self.key_manager.load_public_key(self.key_manager.get_security_param("rsa_user_public_key"))
        e_h = bytes.fromhex(self.key_manager.get_security_param("e_h"))
        e_h_sig = bytes.fromhex(self.key_manager.get_security_param("e_h_sig"))
        # now check before the run that no immutable files have changed, based on stored hash
        if train_dir:
            immutable_files = self._parse_files(train_dir)
            immutable_files = [str(file) for file in immutable_files if "train_config.json" not in str(file)]

            current_hash = hash_immutable_files(immutable_files, str(self.key_manager.get_security_param("user_id")),
                                                bytes.fromhex(self.key_manager.get_security_param("session_id")))
        elif files:
            current_hash = hash_immutable_files(files,
                                                str(self.key_manager.get_security_param("user_id")),
                                                bytes.fromhex(self.key_manager.get_security_param("session_id")),
                                                binary_files=True
                                                )
        print("e_h", e_h)
        print("file hash", current_hash)
        # Verify that the hash value corresponds with the signature
        user_pk.verify(e_h_sig,
                       current_hash,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                   salt_length=padding.PSS.MAX_LENGTH),
                       utils.Prehashed(hashes.SHA512()))
        if e_h != current_hash:
            raise ValidationError("Immutable Files")

    def validate_previous_results(self, files: List[BinaryIO] = None):
        """
        Verify that the results from the execution of the previous station did not change, by hashing the stored results
        from the previous station and comparing it with the decrypted stored hash from the previous station
        """
        # verify the hash of the results of the previous station
        prev_results_hash = self.key_manager.get_security_param("e_d")
        results_sig = self.key_manager.get_security_param("e_d_sig")
        # Load the public key of the station
        ds = self.key_manager.get_security_param("digital_signature")
        # Get public key of the previous station
        station_public_key = self.key_manager.get_security_param("rsa_public_keys")[ds[-1]["station"]]
        station_public_key = self.key_manager.load_public_key(station_public_key)
        if files:
            results_hash = hash_results(files,
                                        session_id=bytes.fromhex(self.key_manager.get_security_param("session_id")),
                                        binary_files=True)
        else:
            files = self._parse_files(self.results_dir)
            results_hash = hash_results(files, bytes.fromhex(self.key_manager.get_security_param("session_id")))
        station_public_key.verify(bytes.fromhex(results_sig),
                                  results_hash,
                                  padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                              salt_length=padding.PSS.MAX_LENGTH),
                                  utils.Prehashed(hashes.SHA512()))
        # Compare with the files currently present in the train
        if results_hash != bytes.fromhex(prev_results_hash):
            raise ValidationError("The previously hashed results do not match the stored ones")

    def sign_digital_signature(self, pk: RSAPrivateKey):
        """
        Update the digital signature of the train after successful execution of the train.
        If there is no previous signature present creates a signature based on the session id, otherwise the
        signature of the previous station is loaded, signed using the current stations private key and appended to
        the list of signatures stored in the train.

        :param pk: private key of the currently running station
        """
        ds = self.key_manager.get_security_param("digital_signature")
        hasher = hashes.Hash(hashes.SHA512(), default_backend())
        if ds is None:
            hasher.update(bytes.fromhex(self.key_manager.get_security_param("session_id")))
            digest = hasher.finalize()
            sig = pk.sign(digest,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512())
                          )
            ds = [{"station": self.station_id, "sig": (sig.hex(), digest.hex())}]
            self.key_manager.set_security_param("digital_signature", ds)
        else:
            # TODO do we need to add the session key here?
            hasher.update(bytes.fromhex(ds[-1]["sig"][0]))
            digest = hasher.finalize()
            sig = pk.sign(digest,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512())
                          )
            ds.append({"station": self.station_id, "sig": (sig.hex(), digest.hex())})
            self.key_manager.set_security_param("digital_signature", ds)

    def verify_digital_signature(self):
        """
        Verifies the digital signature of the train by iterating over the list of signatures and verifying each one
        using the correct public key stored in the train configuration json

        :raise: InvalidSignatureError if any of the signed values can not be validated using the provided public keys

        """
        ds = self.key_manager.get_security_param("digital_signature")
        for sig in ds:
            public_key = self.key_manager.load_public_key(
                self.key_manager.get_security_param("rsa_public_keys")[sig["station"]])
            public_key.verify(bytes.fromhex(sig["sig"][0]),
                              bytes.fromhex(sig["sig"][1]),
                              padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                              utils.Prehashed(hashes.SHA512())
                              )

    def _is_first_station_on_route(self):
        """
        Returns true if current station is the first station on the route
        :return:
        """
        # Check if there are previous results if not station is first station on route
        return self.key_manager.get_security_param("e_d") is None

    @staticmethod
    def _parse_files(dir):
        """
        Parses the exported files from a container and sorts them into relevant categories
        :param dir: directory in which to find all files
        :return: Tuple consisting of lists of paths for the different file types
        """
        files = list()
        print("Detecting files...", end=" ")
        for (dir_path, dir_names, file_names) in os.walk(dir):
            files += [os.path.join(dir_path, file) for file in file_names]
        print(f"Found {len(files)} Files")
        return files

    def _is_last_station_on_route(self):
        # TODO how to check for last station
        return True

    def _previous_station_id(self):
        """
        :return: station id of previous station on route
        """
        # get the key of the last entry in the ds dictionary as the previous station id
        return self.key_manager.get_security_param("digital_signature")[-1]["station"]
