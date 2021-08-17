[![Documentation Status](https://readthedocs.org/projects/train-container-library/badge/?version=latest)](https://train-container-library.readthedocs.io/en/latest/?badge=latest)
![coverage](https://gitlab.com/PersonalHealthTrain/implementations/germanmii/difuture/train-container-library/badges/master/coverage.svg)

# Train Container Library

Python library for pht-train images/containers.

## Docker Images

The docker images defined by the Dockerfiles in the `docker` are the master images that need to be used when building
train images.


## Tests

Run the tests to validate the security protocol is working as intended. From this projects root directory run 
`pytest train_lib`

### Available Images

- `master/python:slim`: Alpine linux image with python 3.8 and the security protocol installed.
- `master/python:ubuntu`: Ubuntu 20.04 image also with python 3.8 and the security protocol installed
- `master/python:dl`: GPU enabled Ubuntu 18.04 image with tensorflow and pytorch and the SP preinstalled
- `master/python:ml`: Ubuntu 20.04 image with additional ml libraries (sklearn, pandas, etc) installed
- `master/r:ml`: Ubuntu 20.04 image with R and r machine learning packages installed


## Security Protocol

The pht security protocol adapted from `docs/Secure_PHT_latest__official.pdf` performs two main tasks:

1. Before executing a train-image on the local machine, unless the station is the first station on the route, the
   previous results need to be decrypted and the content of the image needs to be validated based on the configuration
   of the individual train -> `pre-run`.
2. After executing the train the updated results need to be encrypted and the train configuration needs to be updated to
   reflect the current state ->`post-run`.

To function the protocol expects two environment variables to be set:

1. `STATION_ID` String identifier that has public key/s registered with the central service
2. `RSA_STATON_PRIVATE_KEY` Hex string containing the private key to be used for decryption and signing.

### Pre-run protocol

The pre-run protocol consists of the following steps

1. The hash of the immutable files (train definition) is verified making sure that the executable files did not change
   during the the train definition.
2. The digital signature is verified ensuring the correctness of the results at each stop of the train.
3. The symmetric key is decrypted using the provided station private key
4. The mutable files in `/opt/pht_results` are decrypted using the symmetric key obtained in the previous step
5. The decrypted files are hashed and the hash is compared to the one stored in the train configuration file.

Once these steps have been completed the image is ready to be executed.

### Post-run protocol

1. Calculate the hash of the newly generated results
2. Sign the hash of the results using the provided `RSA_STATION_PRIVATE_KEY`
3. Update the the train signature using the session id that is randomly generated at each execution step
4. Encrypt the resulting files using a newly generated symmetric key
5. Encrypt the generated symmetric key with the public keys of the train participants
6. Update the train configuration file

With the completion of these steps the train is ready to be pushed into the registry for further processing









