import os
import argparse
from train_lib.security import SecurityProtocol


def pre_run_protocol():
    print("Executing pre run protocol")


def post_run_protocol():
    print("Executing post run protocol")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="the command the security protocol should execute one of: \n- pre-run \n- "
                                        "post-run")
    args = parser.parse_args()

    if args.command == "pre-run":
        pre_run_protocol()
    elif args.command == "post-run":
        post_run_protocol()

    else:
        raise ValueError(f"Command {args.command} not recognized. Available commands are: pre-run, post-run")
