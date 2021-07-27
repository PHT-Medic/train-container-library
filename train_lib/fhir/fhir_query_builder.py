import os
from typing import Union, List
import json
from io import BytesIO


def build_query_string(query_dict: dict) -> str:
    query_string = ""
    query_string += query_dict["resource"] + "?"

    # check if there are search parameters given for the main resource
    if query_dict.get("parameters", None):
        # generate the url string for the main resources parameters
        query_string += process_main_resource_parameters(query_dict["parameters"])
    return query_string


def process_main_resource_parameters(resource_params: List[dict]) -> str:
    param_search_string = ""
    for i, parameter in enumerate(resource_params):
        param_search_string += f"{parameter['variable']}={parameter['condition']}"
        if i < len(resource_params) - 1:
            param_search_string += "&"

    return param_search_string


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
