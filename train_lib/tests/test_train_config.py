# import os
#
# import pytest
#
# from train_lib.security.train_config import TrainConfig
#
#
# @pytest.fixture
# def config_dict():
#     config_dict = {
#         "@id": "test_train_id",
#         "session_id": os.urandom(32).hex(),
#         "proposal_id": "test_proposal_id",
#         "source": {
#             "type": "docker_repository",
#             "tag": "latest",
#             "address": "test_repository",
#         },
#         "creator": {
#             "id": "test_creator_id",
#             "rsa_public_key": os.urandom(32).hex(),
#         },
#         "route": [
#             {
#                 "station": "test_station_1",
#                 "eco_system": "padme",
#                 "rsa_public_key": os.urandom(32).hex(),
#                 "index": 0,
#             },
#             {
#                 "station": "test_station_2",
#                 "rsa_public_key": os.urandom(32).hex(),
#                 "eco_system": "tue",
#                 "index": 1,
#             },
#         ],
#         "file_list": ["test_train/entrypoint.py", "test_train/requirements.txt"],
#         "hash": os.urandom(16).hex(),
#         "signature": os.urandom(32).hex(),
#         "@context": {"link": "https://www.w3.org/2018/credentials/v1"},
#         "build": {
#             "signature": os.urandom(32).hex(),
#             "rsa_public_key": os.urandom(32).hex(),
#         },
#     }
#     return config_dict
#
#
# def test_config_init(config_dict):
#     config = TrainConfig(**config_dict)
#     assert config.id == config_dict["@id"]
#
#     print(TrainConfig.schema_json(indent=2))
#     with open("./config_schema.json", "w") as f:
#         f.write(TrainConfig.schema_json(indent=2))
