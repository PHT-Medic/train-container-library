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

    if not station_id:
        raise ValueError("STATION_ID environment variable is not set")
    if not private_key_path:
        raise ValueError("PRIVATE_KEY_PATH environment variable is not set")

    if not os.path.isfile(private_key_path):
        raise FileNotFoundError(f"Private key file not found at {private_key_path}")

    image = args[1]
    config = extract_train_config(image)

    protocol = SecurityProtocol(station_id=station_id, config=config)
    if protocol_step == Commands.PRE:
        protocol.pre_run_protocol(img=image, private_key_path=private_key_path)

    elif protocol_step == Commands.POST:
        protocol.post_run_protocol(
            img=image, private_key_path=private_key_path, rebase=False
        )
