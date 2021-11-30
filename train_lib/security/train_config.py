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


class StationPK(BaseModel):
    station_id: Union[int, str]
    rsa_public_key: HexString


class UserKeys(BaseModel):
    user_id: Union[int, str]
    paillier_public_key: HexString
    rsa_public_key: Optional[HexString] = None


class EncryptedSymKey(BaseModel):
    station_id: Union[int, str]
    sym_key: HexString


class StationSignature(BaseModel):
    sig: HexString
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
    user_keys: UserKeys
    encrypted_keys: Optional[List[EncryptedSymKey]] = None
    station_public_keys: List[StationPK]
    immutable_file_list = List[str]
    immutable_file_hash: HexString  # e_h
    immutable_file_signature: HexString  # e_h_sig
    results_hash: HexString  # e_d
    results_signature: HexString  # e_d_sig
    digital_signature: List[DigitalSignature]
    user_he_key: str
    user_encrypted_sym_key: Optional[HexString] = None
