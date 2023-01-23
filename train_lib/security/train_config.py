from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field


class HexString(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str) or isinstance(v, bytes):
            raise ValueError(f"{v} only string and byte values allowed as input")

        if isinstance(v, str):
            try:
                return cls(v)
            except ValueError:
                raise ValueError(f"{v} is not a valid hex string")
        if isinstance(v, bytes):
            return cls(v.hex())

    def get_bytes(self):
        return bytes.fromhex(self)


class Ecosystem(str, Enum):
    TUE = "tue"
    AAC = "padme"


class StationPublicKeys(BaseModel):
    station_id: Union[int, str]
    rsa_public_key: HexString
    eco_system: Ecosystem


class UserPublicKeys(BaseModel):
    user_id: Union[int, str]
    rsa_public_key: HexString
    paillier_public_key: Optional[Union[HexString, int, str]] = None


class StationSignature(BaseModel):
    digest: HexString
    signature: HexString


class DigitalSignature(BaseModel):
    station_id: Union[int, str]
    signature: StationSignature


class Creator(BaseModel):
    id: Union[int, str]
    rsa_public_key: HexString
    paillier_public_key: Optional[Union[HexString, int, str]] = None
    encrypted_key: Optional[HexString] = None


class RouteEntry(BaseModel):
    station: Union[int, str]
    eco_system: Ecosystem
    rsa_public_key: HexString
    index: int
    signature: Optional[StationSignature] = None
    encrypted_key: Optional[HexString] = None


class TrainSourceType(str, Enum):
    DOCKER = "docker_repository"
    GIT = "git_repository"


class TrainSource(BaseModel):
    type: TrainSourceType
    address: str
    tag: Optional[str] = None
    branch: Optional[str] = None


class BuildSignature(BaseModel):
    signature: HexString
    rsa_public_key: HexString


class TrainConfig(BaseModel):
    source: TrainSource
    creator: Creator
    proposal_id: Union[int, str]
    id: str = Field(alias="@id")
    context: dict = Field(default=None, alias="@context")
    session_id: HexString
    route: List[RouteEntry]
    file_list: List[str]
    hash: HexString  # e_h
    signature: HexString  # e_h_sig
    build: BuildSignature
    result_hash: Optional[HexString] = None  # e_d
    result_signature: Optional[HexString] = None  # e_d_sig

    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True


# https://github.com/samuelcolvin/pydantic/issues/889#issuecomment-850312496
