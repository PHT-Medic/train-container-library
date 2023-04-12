from enum import Enum


class TrainPaths(Enum):
    IMMUTABLE_DIR = "/opt/pht_train"
    RESULT_DIR = "/opt/pht_results"
    CONFIG_PATH = "/opt/train_config.json"


class TrainTags(Enum):
    LATEST = "latest"
    BASE = "base"
    DECRYPTED = "decrypted"
