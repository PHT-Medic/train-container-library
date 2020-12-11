Security
============
This module is responsible for securing the transfer of result files contained in the docker images that represent
PHT Trains. This is done by encrypting the resulting files using envelope encryption.

Additionally the progression of the train, the validity of the image and the results, as well as the identities of the
participating stations are validated before a participant executes a train image.
    TODO add link to paper
A more detailed description of the steps involved in the Protocol refer [link to paper].

The different stages of this protocol are used in the main DAG used by the pht station [link to station docu, repo]
but can also be used independently i.e. to to offer decryption of result to authorized users at a station.


    TODO add images showing how the security protocol works


The classes and functions implementing the security protocol are documented in the following sections.

Security Protocol
-----------------

.. automodule:: train_lib.security.SecurityProtocol
    :members:
    :undoc-members:
    :show-inheritance:

Key Manager
-----------

.. automodule:: train_lib.security.KeyManager
    :members:
    :undoc-members:
    :show-inheritance:

Hashing
-------

.. automodule:: train_lib.security.Hashing
    :members:
    :undoc-members:
    :show-inheritance:

Symmetric Encryption
--------------------

.. automodule:: train_lib.security.SymmetricEncryption
    :members:
    :undoc-members:
    :show-inheritance:


