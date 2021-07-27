import os
from typing import Union
import json


def build_query_string(query_json: Union[str, os.PathLike, bytes]):
    query_dict = load_query_file(query_json)


def process_json_query(query_dict: dict) -> str:
    pass


def load_query_file(query_json: Union[str, os.PathLike, bytes]) -> dict:
    """
    Load a give json file defining the fhir query into a dictionary
    :param query_json:
    :return:
    """
    if isinstance(query_json, str) or isinstance(query_json, bytes):
        query_dict = json.loads(query_json)
        return query_dict
    elif isinstance(query_json, os.PathLike):
        with open(query_json) as f:
            query_dict = json.load(fp=f)
        return query_dict
    else:
        raise ValueError("Unsupported file type for query definition.")
