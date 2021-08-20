import os
from typing import Union, List
import json


def build_query_string(query_dict: dict) -> str:
    """
    Builds a valid query string to perform a get request against a fhir server based on the given dictionary
    containing the definition of a fhir query in json format.

    :param query_dict: dictionary defining fhir search parameters
    :return:
    """
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
    """
    Build the query parameters to be applied directly to queried fhir resource.
    :param resource_params: List of dictionary containing the name of the parameter to search and the search condition
    :return: part of
    """
    param_search_string = ""
    for i, parameter in enumerate(resource_params):
        if isinstance(parameter["condition"], list):
            param_search_string += f"{parameter['variable']}={','.join(parameter['condition'])}"
        else:
            param_search_string += f"{parameter['variable']}={parameter['condition']}"
        # dont add an additional & at the end
        if i < len(resource_params) - 1:
            param_search_string += "&"

    return param_search_string


def process_reverse_chain_params(resource: str, reverse_chains: List[dict]) -> str:
    """
    Creates a query string based on the given reverse chain parameters for the queried resource (querying based on
    other resources that refer to the resource.
    :param resource: the main resource on which to query references
    :param reverse_chains: list of reverse chain resources and parameters
    :return: query string to use in fhir search
    """

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
