Security
============
This module is responsible for securing the transfer of result files contained in the docker images that represent
PHT Trains. This is done by encrypting the resulting files using envelope encryption.

Additionally the progression of the train, the validity of the image and the results, as well as the identities of the
participating stations are validated before a participant executes a train image.

Security Protocol
-----------------

.. automodule:: train_lib.security.SecurityProtocol
    :members:
    :undoc-members:
    :show-inheritance:

