import click
import os
import sys

from train_lib.security.protocol import SecurityProtocol
from train_lib.docker_util.docker_ops import extract_train_config, extract_query_json
import docker


@click.command()
@click.argument("step", type=click.Choice(["pre-run", "post-run", "full"]))
@click.argument("train_image", type=str)
@click.option("station_id", "--station-id", "-i", type=str, required=True)
@click.option(
    "private_key_path",
    "--private-key",
    "-k",
    type=click.Path(exists=True),
    required=True,
)
@click.option(
    "private_key_password",
    "--pk-password",
    "-p",
    type=str,
    required=False,
    default=None,
)
def protocol(step, train_image, station_id, private_key_path, private_key_password):
    client = docker.from_env()
    client.images.pull(train_image)
    config = extract_train_config(train_image)
    protocol = SecurityProtocol(config=config, station_id=station_id)
    if step == "pre-run":
        protocol.pre_run_protocol(
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
        query = extract_query_json(train_image)
    elif step == "post-run":
        protocol.post_run_protocol(
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
    elif step == "full":
        protocol.pre_run_protocol(
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
        # execute the image
        container = client.containers.run(train_image, detach=True)
        container.wait()
        print(container.logs())

        protocol.post_run_protocol(
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )


if __name__ == "__main__":
    protocol()
