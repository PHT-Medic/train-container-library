import os
import argparse
from train_lib.security.SecurityProtocol import SecurityProtocol
from dotenv import load_dotenv, find_dotenv


def main():
    """
    Execute the security protocol based on command line arguments

    :return:
    :rtype:
    """
    # TODO check for key formats
    os.environ["RSA_STATION_PRIVATE_KEY"] = hex_private_key
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="the command the security protocol should execute one of: \n- pre-run \n- "
                                        "post-run")
    args = parser.parse_args()
    # TODO get environment variables
    sp = SecurityProtocol(station_id=os.getenv("STATION_ID"), config_path=os.path.abspath("../test/train_config.json"),
                          results_dir=os.path.abspath("../test/example_results"), train_dir="../scripts")

    if args.command == "pre-run":
        sp.pre_run_protocol()
    elif args.command == "post-run":
        sp.post_run_protocol()

    else:
        raise ValueError(f"Command {args.command} not recognized. Available commands are: pre-run, post-run")


if __name__ == '__main__':
    load_dotenv(find_dotenv())
    # TODO remove this
    with open("../test/keys/station_tuebingen_private_key.pem" , "rb") as private_key:
        station_private_key = private_key.read()
        hex_private_key = station_private_key.hex()
    os.environ["RSA_STATION_PRIVATE_KEY"] = hex_private_key

    main()

