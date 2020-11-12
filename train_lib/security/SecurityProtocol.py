from .KeyManager import KeyManager
from .SymmetricEncryption import FileEncryptor
from .SecurityErrors import ValidationError
from .Hashing import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding
import pickle
import glob
import os


class SecurityProtocol:
    """
    Class that performs the security protocol outlined in the security concept
    """

    def __init__(self, station_id: str, config_path: str = "/opt/pht_train/train_config.json",
                 results_dir: str = "/opt/pht_results", train_dir: str = "/opt/pht_train"):
        self.station_id = station_id
        self.key_manager = KeyManager(config_path=config_path)
        self.results_dir = results_dir
        self.train_dir = train_dir

    def pre_run_protocol(self):
        """
        Decrypts the files contained in the train. And performs the steps necessary to validate a train before it is
        being run
        :return:
        """
        # TODO adapt to new platform/ how to get the files?

        # print(response)
        self.validate_immutable_files(self.train_dir)

        if not self._is_first_station_on_route():
            self.verify_digital_signature()

            files = self._parse_files(self.results_dir)

            file_encryptor = FileEncryptor(self.key_manager.get_sym_key(self.station_id))

            # Decrypt all previously encrypted files
            file_encryptor.decrypt_files(files)
            self.validate_previous_results()

    def post_run_protocol(self):
        """
        Updates the necessary values and encrypts the updated files after the train is run
        :return:
        """
        # Update the values hash and signature of the results

        files = self._parse_files(self.results_dir)
        e_d = hash_results(files, self.key_manager.get_security_param("session_id"))
        self.key_manager.set_security_param("e_d", e_d.hex())
        # TODO check on how to get the key
        sk = self.key_manager.load_private_key("RSA_STATION_PRIVATE_KEY")
        e_d_sig = sk.sign(e_d,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512()))
        self.key_manager.set_security_param("e_d_sig", e_d_sig.hex())
        # Sign the train after execution
        self.sign_digital_signature()
        # Write new values to file and encrypt files with new symmetric key
        new_sym_key = self.key_manager.generate_symmetric_key()
        file_encryptor = FileEncryptor(new_sym_key)

        response = file_encryptor.encrypt_files(files)
        # TODO needs ti be changed based on last station/ using keys of all stations on route
        self.key_manager.set_security_param("encrypted_key", self.key_manager.encrypt_symmetric_key(new_sym_key))
        # at the last station encrypt the symmetric key using the rsa public key of the user
        if self._is_last_station_on_route():
            user_public_key = self.key_manager.load_public_key(self.key_manager.get_security_param("rsa_user_public_key"))
            user_encrypted_sym_key = self.key_manager._rsa_pk_encrypt(new_sym_key, user_public_key)
            self.key_manager.set_security_param("user_encrypted_sym_key", user_encrypted_sym_key)
        self.key_manager.save_keyfile()

    def validate_immutable_files(self, train_dir: str):
        """
        Checks if the hash of the immutable files is the same as the one stored at the creation of the train
        """
        # check the signature of the stored hash value using ec signature verifying that it is created by the user
        user_pk = self.key_manager.load_public_key(self.key_manager.get_security_param("rsa_user_public_key"))
        e_h = bytes.fromhex(self.key_manager.get_security_param("e_h"))
        e_h_sig = bytes.fromhex(self.key_manager.get_security_param("e_h_sig"))
        # now check before the run that no immutable files have changed, based on stored hash

        immutable_files = self._parse_files(train_dir)
        # TODO exclude train_config.json
        immutable_files = [str(file) for file in immutable_files if "train_config.json" not in str(file)]

        current_hash = hash_immutable_files(immutable_files, str(self.key_manager.get_security_param("user_id")),
                                            bytes.fromhex(self.key_manager.get_security_param("session_id")))

        user_pk.verify(e_h_sig,
                       current_hash,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                   salt_length=padding.PSS.MAX_LENGTH),
                       utils.Prehashed(hashes.SHA512()))
        if e_h != current_hash:
            raise ValidationError("Immutable Files")

    def validate_previous_results(self):
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

    def sign_digital_signature(self):
        """
        Signs the train after the execution of the algorithm
        """
        pk = self.key_manager.load_private_key("RSA_STATION_PRIVATE_KEY")
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
        # TODO is previous station id available??
        else:
            # TODO check this
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
        Verifies the digital signature of the train hereby validating the route etc
        """
        # TODO check byte conversion
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
        # TODO change this to a more secure way/based on station id and route
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
        print("parsing files")
        for (dir_path, dir_names, file_names) in os.walk(dir):
            files += [os.path.join(dir_path, file) for file in file_names]
        return files

    def _is_last_station_on_route(self):
        # TODO how to check for last station
        return True

    def _previous_station_id(self):
        """
        :return: station id of previous station on route
        """
        # get the key of the last entry in the ds dictionary as the previous station id
        return self.key_manager.get_security_param("digital_signature")[-1]

    def _next_station_id(self):
        """
        Returns the next station id, assuming that station ids are linearly ordered integers
        :return:
        """
        # TODO change to be based on route with nonlinear route ids
        return self.station_id + 1
