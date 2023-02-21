[![Documentation Status](https://readthedocs.org/projects/train-container-library/badge/?version=latest)](https://train-container-library.readthedocs.io/en/latest/?badge=latest)
[![CodeQL](https://github.com/PHT-Medic/train-container-library/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/PHT-Medic/train-container-library/actions/workflows/codeql-analysis.yml)
[![main-ci](https://github.com/PHT-EU/train-container-library/actions/workflows/main.yml/badge.svg)](https://github.com/PHT-EU/train-container-library/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/PHT-Medic/train-container-library/branch/master/graph/badge.svg?token=11RYRZK2FO)](https://codecov.io/gh/PHT-Medic/train-container-library)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pht-train-container-library)
![PyPI - Downloads](https://img.shields.io/pypi/dw/pht-train-container-library)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# &#128646; Train Container Library

Python library for validating and interacting with pht-train images/containers.

## Installation

```shell
pip install pht-train-container-library
```


## Setup development environment
Make sure you have [poetry](https://python-poetry.org/docs/#installation) and [pre-commit](https://pre-commit.com/#install) installed.

Install the dependencies and pre-commit hooks:
```shell
poetry install --with dev
```

```shell
poetry run pre-commit install
```

### Run tests

```shell
poetry run pytest
```

### Linting and formatting

These commands are also run as pre-commit hooks.

Linting with ruff:
```shell
poetry run ruff . --fix
```

Formatting with black:
```shell
poetry run black .
```

## Security Protocol

The pht security protocol adapted from `docs/Secure_PHT_latest__official.pdf` performs two main tasks:

1. Before executing a train-image on the local machine, unless the station is the first station on the route, the
   previous results need to be decrypted and the content of the image needs to be validated based on the configuration
   of the individual train -> `pre-run`.
2. After executing the train the updated results need to be encrypted and the train configuration needs to be updated to
   reflect the current state ->`post-run`.

### Train image structure

To ensure the protocol is working correctly train docker images are required to keep the following structure:

- `/opt/train_config.json`: Stores the configuration file of the train.
- `/opt/pht_train/`: Stores all the files containing code or other things required for the train algorithm to run. The
  contents of this directory can never change and is validated by the `pre-run` step.
- `/opt/pht_results/`: Stores the results of the train. Which will be decrypted in the `pre-run` step and encrypted in
  the `post-run` step.

No files in the image outside the `/opt/pht_results/` directory should change during the execution of the algorithm.

### Usage - Python Script

To use the protocol in your own python application, after installing the library
with `pip install pht-train-container-library` an instance of the protocol can be to validate docker images as follows:

```python
from train_lib.security.protocol import SecurityProtocol
from train_lib.docker_util.docker_ops import extract_train_config

image_name = '<image-repo>:<image-tag>'
station_id = '<station-id>'

# Get the train configuration from the image
config = extract_train_config(image_name)
# Initialize the protocol with the extracted config and station_id
protocol = SecurityProtocol(station_id=station_id, config=config)

# execute one of the protocol steps
protocol.pre_run_protocol(image_name, private_key_path='<path-to-private-key>')
# protocol.post_run_protocol(image_name, private_key_path='<path-to-private-key>')
```

### Usage - Container

A containerized version of the protocol is also available it can be used with the following command:

```shell
docker run -e STATION_ID=<station_id> -e PRIVATE_KEY_PATH=/opt/private_key.pem -v /var/run/docker.sock:/var/run/docker.sock -v <path_to_your_key>:/opt/private_key.pem ghcr.io/pht-medic/protocol <pre-run/post-run> <image-repo>:<image-tag>
```

`STATION_ID` and `PRIVATE_KEY_PATH` are required to be set in the environment variables. As well as passing the docker
socket `/var/run/docker.sock` to the container as a volume to enable docker-in-docker functionality.

### Pre-run protocol

The pre-run protocol consists of the following steps

1. The train files are decrypted using an encrypted symmetric key that is decrypted using the provided station private key
2. The hash of the immutable files (train definition) is verified making sure that the executable files did not change
   during the train definition.
3. The build signature is verified ensuring that this image was build by the given user
4. The digital signature is verified ensuring the correctness of the results at each stop of the train.
5. The symmetric key is decrypted using the provided station private key
6. The mutable files in `/opt/pht_results` are decrypted using the symmetric key obtained in the previous step
7. The decrypted files are hashed and the hash is compared to the one stored in the train configuration file.

Once these steps have been completed the image is ready to be executed.

### Post-run protocol

1. Calculate the hash of the newly generated results
2. Sign the hash of the results using the provided `PRIVATE_KEY_PATH`
3. Update the the train signature using the session id that is randomly generated at each execution step
4. Encrypt the resulting files using a newly generated symmetric key
5. Encrypt the generated symmetric key with the public keys of the train participants
6. Encrypt the train files using the symmetric key
6. Update the train configuration file and train image

With the completion of these steps the train is ready to be pushed into the registry for further processing

## Tests

Run the tests to validate the security protocol is working as intended. From this projects root directory run
`poetry run pytest train_lib`







