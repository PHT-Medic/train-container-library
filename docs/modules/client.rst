Clients
===========

This module implements classes for interacting with different services utilized in
the PHT.

PHT Client
----------
Client for interacting with the central user interface and for publishing messages to a
message queue.

.. automodule:: train_lib.clients.pht_client
    :members:
    :undoc-members:
    :show-inheritance:


RabbitMQ Consumer
-----------------
Generalized `RabbitMQ <https://www.rabbitmq.com/>`_ consumer that handles setup and
error handling for processing a message queue.
Override the ``on_message(..)`` method to process the received messages

.. automodule:: train_lib.clients.rabbitmq
    :members:
    :undoc-members:
    :show-inheritance:


