import os
import sys
from enum import Enum

from train_lib.docker_util.docker_ops import extract_train_config
from train_lib.security.protocol import SecurityProtocol


class Commands(Enum):
    PRE = "pre-run"
    POST = "post-run"


if __name__ == "__main__":
    args = sys.argv[1:]

    protocol_step = Commands(args[0])
    station_id = os.getenv("STATION_ID")
    private_key_path = os.getenv("PRIVATE_KEY_PATH")

    assert station_id and private_key_path

    image = args[1]
    config = extract_train_config(image)

    protocol = SecurityProtocol(station_id=station_id, config=config)
    if protocol_step == Commands.PRE:
        protocol.pre_run_protocol(img=image, private_key_path=private_key_path)

    elif protocol_step == Commands.POST:
        protocol.post_run_protocol(img=image, private_key_path=private_key_path)
