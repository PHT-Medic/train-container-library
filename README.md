# Train Container Library
Python library for pht-train images/containers.

## Security Protocol
The pht security protocol adapted from `docs/Secure_PHT_latest__official.pdf` performs two main tasks:
1. Before executing a train-image on the local machine, unless the station is the first station on the route, the 
previous results need to be decrypted and the content of the image needs to be validated based on the configuration of 
the individual train -> `pre-run`.
2. After executing the train the updated results need to be encrypted and the train configuration needs to be updated
to reflect the current state ->`post-run`.


To function properly the protocol expects two ennvironment variables to be set:
1. `STATION_ID` String identifier that has public key/s registered with the central service
2. `RSA_STATON_PRIVATE_KEY` Hex string containing the private key to be used for decryption and signing.


### Pre-run protocol


### Post-run protocol



## Docker Images
The docker images in 

### Available Images






