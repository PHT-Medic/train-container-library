import os
import argparse
from train_lib.security.SecurityProtocol import SecurityProtocol
from dotenv import load_dotenv, find_dotenv


def pre_run_protocol():
    print("Executing pre run protocol")
    sp = SecurityProtocol(station_id="1", config_path=os.path.abspath("../test/train_config.json"),
                          results_dir=os.path.abspath("../test/example_results"))
    sp.pre_run_protocol()


def post_run_protocol():
    print("Executing post run protocol")


if __name__ == '__main__':
    load_dotenv(find_dotenv())
    print(os.getenv("STATION_SK_1"))
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

