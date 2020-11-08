from cryptography.fernet import Fernet


class FileEncryptor:
    """
    Performs symmetric encryption and decryption of sensitive files belonging to the train cargo
    """

    def __init__(self, key):
        self.fernet = Fernet(key)

    def encrypt_files(self, response):
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        result = {}
        types_to_decrypt = {'ModelFile', 'QueryFile'}
        for (path, (type, decrypted)) in response.items():
            if type in types_to_decrypt:
                encrypted = self.fernet.encrypt(decrypted)
                result[path] = (type, encrypted)
            else:
                result[path] = (type, decrypted)
        return result

    def decrypt_files(self, response):
        """
        Decrypt the given files using symmetric encryption
        :return:
        """
        result = {}
        types_to_decrypt = {'ModelFile', 'QueryFile'}
        for (path, (type, encrypted)) in response.items():
            if type in types_to_decrypt:
                decrypted = self.fernet.decrypt(encrypted)
                result[path] = (type, decrypted)
            else:
                result[path] = (type, encrypted)
        return result
