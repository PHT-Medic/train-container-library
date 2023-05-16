from io import BytesIO
import json
import click
import os
import sys
import tarfile

from train_lib.security.protocol import SecurityProtocol
from train_lib.docker_util.docker_ops import (
    extract_train_config,
    extract_query_json,
    extract_archive,
    add_archive,
)
import docker


@click.command()
@click.argument("step", type=click.Choice(["pre-run", "post-run", "full", "sim-full"]))
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

    # get the image or pull it

    click.echo("Pulling train image...")
    client.images.pull(train_image)

    # pull base image if not present
    repo = train_image.split(":")[0]
    try:
        click.echo("Pulling base image...")
        client.images.pull(repo, tag="base")
    except Exception as e:
        print(e)
        click.echo("Base image not found. Retagging...")
        # tag the input image as base
        client.images.get(train_image).tag(repo, tag="base")

    config = extract_train_config(train_image)
    protocol = SecurityProtocol(config=config, station_id=station_id)
    if step == "pre-run":
        click.echo("Executing pre-run protocol...")
        debug_run(
            protocol,
            step,
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
    elif step == "post-run":
        click.echo("Executing post-run protocol...")
        debug_run(
            protocol,
            step,
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
    elif step == "full":
        click.echo("Executing pre-run protocol...")
        debug_run(
            protocol,
            "pre-run",
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
        click.echo("Executing train image...")
        # execute the image
        container = client.containers.run(train_image, detach=True)
        container.wait()
        container.commit(repository=repo, tag="latest")
        print(container.logs())
        click.echo("Executing post-run protocol...")
        debug_run(
            protocol,
            "post-run",
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )

    # run pre-run protocol add a fake results file to the image and then run post run protocol
    elif step == "sim-full":
        debug_run(
            protocol,
            "pre-run",
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
        # todo add a fake results file

        # generate a fake results file
        archive = make_fake_results_archive()
        add_archive(train_image, archive, "/opt/pht_results")

        debug_run(
            protocol,
            "post-run",
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )

    else:
        click.echo("Invalid step. Must be one of: pre-run, post-run, full, sim-full")


def make_fake_results_archive():
    archive = BytesIO()
    results = {"these are": "fake results", "random": os.urandom(10).hex()}

    results_io = BytesIO(json.dumps(results).encode("utf-8"))

    with tarfile.open(fileobj=archive, mode="w") as tar:
        tar.addfile(tarfile.TarInfo("results.json"), results_io)
    archive.seek(0)
    return archive


def debug_run(
    sp: SecurityProtocol,
    step: str,
    train_image: str,
    private_key_path: str,
    private_key_password: str,
):
    display_train_dir(train_image)
    if step == "pre-run":
        sp.pre_run_protocol(
            train_image,
            private_key_path=private_key_path,
            private_key_password=private_key_password,
        )
    elif step == "post-run":
        sp.post_run_protocol(
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
