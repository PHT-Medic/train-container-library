from typing import List, Optional, Union

from pydantic import BaseModel


class HexString(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str) or isinstance(v, bytes):
            raise ValueError(f'{v} only string and byte values allowed as input')

        if isinstance(v, str):
            try:
                hex_bytes = bytes.fromhex(v)
                return cls(v)
            except ValueError:
                raise ValueError(f'{v} is not a valid hex string')
        if isinstance(v, bytes):
            return cls(v.hex())

    def get_bytes(self):
        return bytes.fromhex(self)


class StationPublicKeys(BaseModel):
    station_id: Union[int, str]
    rsa_public_key: HexString


class UserPublicKeys(BaseModel):
    user_id: Union[int, str]
    rsa_public_key: HexString
    paillier_public_key: Optional[Union[HexString, int, str]] = None


class EncryptedSymKey(BaseModel):
    station_id: Union[int, str]
    sym_key: HexString


class StationSignature(BaseModel):
    signature: HexString
    digest: HexString


class DigitalSignature(BaseModel):
    station_id: Union[int, str]
    signature: StationSignature


class TrainConfig(BaseModel):
    master_image: str
    user_id: Union[int, str]
    proposal_id: Union[int, str]
    train_id: str
    session_id: HexString
    user_keys: UserPublicKeys
    encrypted_keys: Optional[List[EncryptedSymKey]] = None
    station_public_keys: List[StationPublicKeys]
    immutable_file_list: List[str]
    immutable_file_hash: HexString  # e_h
    immutable_file_signature: HexString  # e_h_sig
    results_hash: Optional[HexString] = None  # e_d
    results_signature: Optional[HexString]  # e_d_sig
    digital_signature: Optional[List[DigitalSignature]] = None
    user_encrypted_sym_key: Optional[HexString] = None

    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True

# https://github.com/samuelcolvin/pydantic/issues/889#issuecomment-850312496