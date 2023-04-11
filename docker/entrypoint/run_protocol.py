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

    if len(args) < 2:
        raise ValueError(
            f"Invalid number of arguments. Expected at least 2 ([0] <protocol-step> [1] <train-image>), [n] options "
            f"got {len(args)}. \n {args}"
        )

    # get rebasing argument
    rebase = False
    if len(args) > 2:
        rebase_arg = args[2]
        if rebase_arg == "--rebase":
            rebase = True
            print("Executing protocol with rebasing configured.")
        else:
            raise ValueError(
                f"Invalid argument. Only --rebase ist allowed as third argument but got: {rebase_arg}"
            )

    protocol_step = Commands(args[0])
    station_id = os.getenv("STATION_ID")
    private_key_path = os.getenv("PRIVATE_KEY_PATH")
    private_key_password = os.getenv("PRIVATE_KEY_PASSWORD")

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
        protocol.pre_run_protocol(
            img=image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )

    elif protocol_step == Commands.POST:
        protocol.post_run_protocol(
            img=image,
            private_key_path=private_key_path,
            rebase=rebase,
            private_key_password=private_key_password,
        )
