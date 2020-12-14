Clients
===========

This module implements classes for interacting with different services utilized in
the PHT.

PHT Client
----------
Client for interacting with the central user interface and for publishing messages to a
message queue.

.. autoclass:: train_lib.client.pht_client.PHTClient
    :members:
    :undoc-members:
    :show-inheritance:


Consumer
--------
Generalized `RabbitMQ <https://www.rabbitmq.com/>`_ consumer that handles setup and
error handling for processing a message queue.
Override the ``on_message(..)`` method to process the received messages

.. autoclass:: train_lib.client.rabbitmq.Consumer
    :members:
    :undoc-members:
    :show-inheritance:


