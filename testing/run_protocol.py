import click
import os
import sys

from train_lib.security.protocol import SecurityProtocol
from train_lib.docker_util.docker_ops import (
    extract_train_config,
    extract_query_json,
    extract_archive,
)
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

    # check the train image
    client = docker.from_env()
    if len(train_image.split(":")) != 2:
        click.echo(
            "Invalid train image name. Must be in the format <image>:<tag>. Adding ':latest'."
        )
        train_image = train_image + ":latest"

    img = client.images.get(train_image)
    if not img:
        click.echo("Image not found. Pulling...")
        client.images.pull(train_image)

    config = extract_train_config(train_image)
    protocol = SecurityProtocol(config=config, station_id=station_id)
    if step == "pre-run":
        debug_pre_run(
            protocol,
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
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


def debug_pre_run(
    sp: SecurityProtocol,
    train_image: str,
    private_key_path: str,
    private_key_password: str,
):
    display_train_dir(train_image)
    sp.pre_run_protocol(
        train_image,
        private_key_path=private_key_path,
        private_key_password=private_key_password,
    )
    display_train_dir(train_image)


def display_train_dir(train_image: str):
    click.echo("Train directory:")
    client = docker.from_env()
    # extract archive from image
    archive = extract_archive(train_image, "/opt")
    # container.wait()
    for m in archive.getmembers():
        if not m.isdir():
            content = archive.extractfile(m)
            file_preview = content.read(100)
            print(f"Train file: {m.name} - {file_preview}")


if __name__ == "__main__":
    protocol()
