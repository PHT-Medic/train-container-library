"""
Specific exceptions that can occur during the security protocol
"""


class ValidationError(Exception):
    """
    Error that occurs if hash values do not match
    """

    def __init__(self, hash_value):
        self.hash_value = hash_value
