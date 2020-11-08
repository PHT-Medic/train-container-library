from .KeyManager import KeyManager
from .SymmetricEncryption import FileEncryptor
from .SecurityErrors import ValidationError
from .Hashing import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding
import pickle


class SecurityProtocol:
    """
    Class that performs the security protocol outlined in the security concept
    """

    def __init__(self, station_id):
        self.station_id = station_id
        self.key_manager = None

    @staticmethod
    def parse_files(response):
        """
        Parses the exported files from a container and sorts them into relevant categories
        :param response: response resulting from a run or describe command
        :return: Tuple consisting of lists of paths for the different file types
        """
        query_files = []
        model_files = []
        algorithm_files = []

        for path in response:
            file_type, file_content = response[path]
            if file_type == "KeyFile":
                key_file = path
            elif file_type == "ModelFile":
                model_files.append(path)
            elif file_type == "AlgorithmFile":
                algorithm_files.append(path)
            elif file_type == "QueryFile":
                query_files.append(path)

        return key_file, algorithm_files, query_files, model_files

    @staticmethod
    def generate_output_files(key_file, model_files, algorithm_files, query_files):
        """
        Formats the new files in the format required by rebasing
        :param key_file:
        :param model_files:
        :param algorithm_files:
        :param query_files:
        :return: List of tuples to be read by the rebasing function
        """
        output_files = [("KeyFile", key_file)]
        for file in algorithm_files:
            output_files.append(("AlgorithmFile", file))
        for file in model_files:
            output_files.append(("ModelFile", file))
        for file in query_files:
            output_files.append(("QueryFile", file))
        return output_files

    def creation_protocol(self):
        """
        Checks if the the train has been executed before if not create the necessary files and values
        :return:
        """
        # TODO temporary solution, needs a lot of changes to go with creation of train/train builder
        if self.train.key_file.exists():
            pass
        else:
            self.key_manager.create_keyfile()
            immutable_hash = hash_immutable_files(self.train, self.key_manager.get_security_param("user_id"),
                                                  self.key_manager.get_security_param("session_id"))
            self.key_manager.set_security_param("e_h", immutable_hash)
            # TODO based on environment variables for now, make based on station provided private key
            sk = self.key_manager.load_private_key("RSA_USER_PRIVATE_KEY")
            immutable_signature = sk.sign(immutable_hash, padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          utils.Prehashed(hashes.SHA512())
                                          )
            self.key_manager.set_security_param("e_h_sig", immutable_signature)
            self.file_encryptor.set_key(self.key_manager.get_sym_key(self.station_id))
            self.file_encryptor.encrypt_files()

    def pre_run_protocol(self, response):
        """
        Decrypts the files contained in the train. And performs the steps necessary to validate a train before it is
        being run
        :return:
        """
        # TODO adapt to new platform/ how to get the files?
        key_file_key, algorithm_files_keys, query_files_keys, model_files_keys = self.parse_files(response)
        key_file = response[key_file_key][1]

        self.key_manager = KeyManager(pickle.loads(key_file))
        file_encryptor = FileEncryptor(self.key_manager.get_sym_key())
        # Decrypt all previously encrypted files
        response = file_encryptor.decrypt_files(response)
        # print(response)
        self.validate_immutable_files(response)

        if not self._is_first_station_on_route():
            self.verify_digital_signature()
            self.validate_previous_results(response)

        return response

    def post_run_protocol(self, response):
        """
        Updates the necessary values and encrypts the updated files after the train is run
        :return:
        """
        # Update the values hash and signature of the results
        model_files = [item[1][1] for item in sorted(list(response), key=lambda x: x[0]) if item[1][0] == 'ModelFile']
        e_d = hash_results(model_files, self.key_manager.get_security_param("session_id"))
        self.key_manager.set_security_param("e_d", e_d)
        # TODO check on how to get the key
        sk = self.key_manager.load_private_key("RSA_STATION_PRIVATE_KEY")
        e_d_sig = sk.sign(e_d,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512()))
        self.key_manager.set_security_param("e_d_sig", e_d_sig)
        # Sign the train after execution
        self.sign_digital_signature()
        # Write new values to file and encrypt files with new symmetric key
        new_sym_key = self.key_manager.generate_symmetric_key()
        file_encryptor = FileEncryptor(new_sym_key)

        response = file_encryptor.encrypt_files(response)
        # TODO needs ti be changed based on last station/ using keys of all stations on route
        self.key_manager.set_security_param("encrypted_key",
                                            self.key_manager.encrypt_symmetric_key(new_sym_key,
                                                                                   self.key_manager.
                                                                                   get_security_param("rsa_public_keys")
                                                                                   [self._next_station_id()]))
        # at the last station encrypt the symmetric key using the rsa public key of the user
        if self._is_last_station_on_route():
            user_encrypted_sym_key = self.key_manager.encrypt_symmetric_key(new_sym_key,
                                                                            self.key_manager.
                                                                            get_security_param("rsa_user_public_key"))
            self.key_manager.set_security_param("user_encrypted_sym_key", user_encrypted_sym_key)
        # TODO check this
        response['/opt/pht_train/keys'] = ('KeyFile', self.key_manager.save_keyfile())
        return response

    def validate_immutable_files(self, response):
        """
        Checks if the hash of the immutable files is the same as the one stored at the creation of the train
        """
        # check the signature of the stored hash value using ec signature verifying that it is created by the user
        user_pk = self.key_manager.load_public_key(self.key_manager.get_security_param("rsa_user_public_key"))
        e_h = self.key_manager.get_security_param("e_h")
        e_h_sig = self.key_manager.get_security_param("e_h_sig")
        # now check before the run that no immutable files have changed, based on stored hash
        response_list = sorted(list(response.items()), key=lambda x: x[0])

        immutable_files = [file[1] for (path, file) in response_list if file[0] in {'AlgorithmFile', 'QueryFile'}]

        current_hash = hash_immutable_files(immutable_files, self.key_manager.get_security_param("user_id"),
                                            self.key_manager.get_security_param("session_id"))

        user_pk.verify(e_h_sig,
                       current_hash,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                   salt_length=padding.PSS.MAX_LENGTH),
                       utils.Prehashed(hashes.SHA512()))
        if e_h != current_hash:
            raise ValidationError("Immutable Files")

    def validate_previous_results(self, response):
        """
        Verify that the results from the execution of the previous station did not change, by hashing the stored results
        from the previous station and comparing it with the decrypted stored hash from the previous station
        """
        # verify the hash of the results of the previous station
        prev_results_hash = self.key_manager.get_security_param("e_d")
        results_sig = self.key_manager.get_security_param("e_d_sig")
        # Load the public key of the station
        station_public_key = self.key_manager.get_security_param("rsa_public_keys")[self._previous_station_id()]
        station_public_key = self.key_manager.load_public_key(station_public_key)

        model_files = [item[1][1] for item in sorted(list(response), key=lambda x: x[0]) if item[1][0] == 'ModelFile']
        results_hash = hash_results(model_files, self.key_manager.get_security_param("session_id"))
        station_public_key.verify(results_sig,
                                  results_hash,
                                  padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                              salt_length=padding.PSS.MAX_LENGTH),
                                  utils.Prehashed(hashes.SHA512()))
        # Compare with the files currently present in the train
        if results_hash != prev_results_hash:
            raise ValidationError("The previously hashed results do not match the stored ones")

    def sign_digital_signature(self):
        """
        Signs the train after the execution of the algorithm
        """
        # TODO make rsa private key of station available
        pk = self.key_manager.load_private_key("RSA_STATION_PRIVATE_KEY")
        ds = self.key_manager.get_security_param("digital_signature")
        hasher = hashes.Hash(hashes.SHA512(), default_backend())
        if ds is None:
            hasher.update(self.key_manager.get_security_param("session_id"))
            digest = hasher.finalize()
            sig = pk.sign(digest,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512())
                          )
            ds = {self.station_id: (sig, digest)}
            self.key_manager.set_security_param("digital_signature", ds)
        else:
            hasher.update(ds[self._previous_station_id()][0])
            digest = hasher.finalize()
            sig = pk.sign(digest,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA512())
                          )
            ds[self.station_id] = (sig, digest)
            self.key_manager.set_security_param("digital_signature", ds)

    def verify_digital_signature(self):
        """
        Verifies the digital signature of the train hereby validating the route etc
        """
        ds = self.key_manager.get_security_param("digital_signature")
        for key in ds:
            public_key = self.key_manager.load_public_key(self.key_manager.get_security_param("rsa_public_keys")[key])
            public_key.verify(ds[key][0],
                              ds[key][1],
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

    def _is_last_station_on_route(self):
        # TODO how to check for last station
        return True

    def _previous_station_id(self):
        """
        :return: station id of previous station on route
        """
        # get the key of the last entry in the ds dictionary as the previous station id
        return self.key_manager.get_security_param("digital_signature").keys()[-1]

    def _next_station_id(self):
        """
        Returns the next station id, assuming that station ids are linearly ordered integers
        :return:
        """
        # TODO change to be based on route with nonlinear route ids
        return self.station_id + 1
