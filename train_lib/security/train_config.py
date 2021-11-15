from typing import List

from pydantic import BaseModel


class StationPK(BaseModel):
    station_id: int
    public_key: str


class EncryptedSymKey(BaseModel):
    station_id: int
    sym_key: str


class StationSignature(BaseModel):
    signature: str
    digest: str


class DigitalSignature(BaseModel):
    station_id: int
    signature: StationSignature


class TrainConfig(BaseModel):
    master_image: str
    user_id: int
    proposal_id: str
    train_id: str
    session_id: str
    rsa_user_public_key: str
    encrypted_key: List[EncryptedSymKey]
    rsa_public_keys: List[StationPK]
    immutable_file_hash: str  # e_h
    immutable_file_signature: str  # e_h_sig
    results_hash: str  # e_d
    results_signature: str  # e_d_sig
    digital_signatures: List[DigitalSignature]
    user_he_key: str
    user_encrypted_sym_key: str
    immutable_file_list = List[str]
