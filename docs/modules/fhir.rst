FHIR
===========

THis module contains the FHIR related functionality of the PHT, which includes generating query URLs,
executing the query against a FHIR server.
It will also store the results in a selected format and check parsed results for k-anonymity.

FHIR Client
----------
Client for interacting with FHIR servers following the v4 FHIR specifications.

.. automodule:: train_lib.fhir.fhir_client
    :members:
    :undoc-members:
    :show-inheritance:


Query building
-----------------
.. automodule:: train_lib.fhir.fhir_query_builder
    :members:
    :undoc-members:
    :show-inheritance:


k-anonymity
-----------
.. automodule:: train_lib.fhir.fhir_k_anonymity
    :members:
    :undoc-members:
    :show-inheritance:
