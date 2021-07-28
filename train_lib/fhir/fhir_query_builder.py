import os
from typing import Union, List
import json
from io import BytesIO


def build_query_string(query_dict: dict) -> str:
    query_string = query_dict["resource"] + "?"

    # check if there are search parameters given for the main resource
    if query_dict.get("parameters", None):
        # generate the url string for the main resources parameters
        query_string += process_main_resource_parameters(query_dict["parameters"])

    # check if there are reverse chain parameters specified and if so append them to the search url
    if query_dict.get("has", None):
        if query_dict.get("parameters", None):
            query_string += "&"
        query_string += process_reverse_chain_params(query_dict["resource"], query_dict["has"])

    return query_string


def process_main_resource_parameters(resource_params: List[dict]) -> str:
    param_search_string = ""
    for i, parameter in enumerate(resource_params):
        param_search_string += f"{parameter['variable']}={parameter['condition']}"
        # dont add an additional & at the end
        if i < len(resource_params) - 1:
            param_search_string += "&"

    return param_search_string


def process_reverse_chain_params(resource: str, reverse_chains: List[dict]) -> str:
    resource_prop = resource.lower()
    reverse_chain_string = ""
    # add all the resources given as reverse chain parameters to the query url
    for i, chain_resource in enumerate(reverse_chains):
        reverse_chain_string += f"_has:{chain_resource['resource']}:{resource_prop}:{chain_resource['property']}="

        # Check if there are multiple conditions given and if so join them with commas
        if isinstance(chain_resource["params"], list):
            reverse_chain_string += ",".join(chain_resource["params"])
        else:
            reverse_chain_string += chain_resource["params"]

        if i < len(reverse_chains) - 1:
            reverse_chain_string += "&"
    return reverse_chain_string


def load_query_file(query_json: Union[str, os.PathLike, bytes]) -> dict:
    """
    Load a give json file defining the fhir query into a dictionary
    :param query_json:
    :return:
    """
    if isinstance(query_json, str):
        try:
            query_dict = json.loads(query_json)
        except json.decoder.JSONDecodeError:
            with open(query_json) as f:
                query_dict = json.load(fp=f)
    elif isinstance(query_json, bytes):
        query_dict = json.loads(query_json)

    elif isinstance(query_json, os.PathLike):
        with open(query_json) as f:
            query_dict = json.load(fp=f)
    else:
        raise ValueError("Unsupported file type for query definition.")

    return query_dict


if __name__ == '__main__':
    query_file = load_query_file("query.json")
    query_string = build_query_string(query_file["query"])
    print(query_string)
