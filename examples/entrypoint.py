import os
import json
import pandas as pd
import pathlib
from dotenv import load_dotenv, find_dotenv

from train_lib.security.homomorphic_addition import secure_addition


DATA_PATH = os.getenv("TRAIN_DATA_PATH")
FHIR_PATH = "/opt/train_data/cord_results.json"
RESULT_PATH = "/opt/pht_results/results.he.json"


def load_if_exists(model_path: str):
    """
    Load previous computed results, if available
    :param model_path: Path of models or results to load
    :return: model
    """
    p = pathlib.Path(model_path)
    if pathlib.Path.is_file(p):
        print("Loading previous results")
        with open(p, "r") as model_file:
            model = json.load(model_file)
        return model
    else:
        return None


def save_results(results, result_path):
    """
    Create (if doesnt exist) a result directory and store the analysis results within
    :param results: Result content
    :param result_path:  Path of results file
    :return: store results as pickle file
    """
    dirPath = "/opt/pht_results"
    try:
        # Create target Directory
        os.mkdir(dirPath)
        print("Directory ", dirPath, " Created (usually done by TB)")
    except FileExistsError:
        print("Directory ", dirPath, " already exists (done by TB)")
    p = pathlib.Path(result_path)
    with open(p, "w") as results_file:
        return json.dump(results, results_file)


def parse_fhir_response() -> pd.DataFrame:
    """
    Load and parse provided FHIR resources to a pandas dataframe
    :return:
    """
    with open(FHIR_PATH, "r") as f:
        results = json.load(f)
    parsed_resources = []
    for patient in results["entry"]:
        resource = patient["resource"]
        parsed_resources.append(parse_resource(resource))

    df = pd.DataFrame(parsed_resources)
    return df


def parse_resource(resource):
    """
    Parse a FHIR resource returned from a FHIR server in a desired format
    :param resource:
    :return: dictionary of parsed resource
    """
    sequence_dict = {
        "givenName": resource["name"][0]["given"],
        "familyName": resource["name"][0]["family"],
        "birthDate": resource["birthDate"],
        "gender": resource["gender"],
    }
    return sequence_dict


def get_user_pk():
    try:
        with open("/opt/train_config.json", "r") as train_conf:
            conf = json.load(train_conf)
            bytes_key = bytes.fromhex(conf["creator"]["paillier_public_key"])
            json_key = json.loads(bytes_key.decode("utf-8"))
            print("User public key n: {}".format(json_key["n"]))
            print("User public key g: {}".format(json_key["g"]))
        return json_key["n"], json_key["g"]
    except Exception:
        return {"user_secure_add_pk": None}


def paillier_addition(prev_result, local_result, number_to_add):
    try:
        curr_result = prev_result["analysis"][number_to_add]
        print(
            "Previous secure addition value from {} {}".format(
                number_to_add, curr_result
            )
        )
    except KeyError:
        print("Previous secure addition from {} empty".format(number_to_add))
        curr_result = None
    user_he_key = get_user_pk()

    return secure_addition(
        local_result, curr_result, int(user_he_key[0]), int(user_he_key[1])
    )


if __name__ == "__main__":
    """
    Main analysis function of the train - the CORD minimal demo for secure calculation of average age
    :return:
    """
    load_dotenv(find_dotenv())
    # parse the FHIR response and load previous results (if available)
    pat_df = parse_fhir_response()
    # Try to load previous results, if no exist create dictionary and print results before execution of analysis
    try:
        results = load_if_exists(RESULT_PATH)
    except FileNotFoundError:
        print("No file available")
    if results is None:
        results = {"analysis": {}, "discovery": {}}
    print("Previous results: {}".format(results))

    # Write analysis code here
    # demo function to calculate average age secure
    now = pd.Timestamp("now")
    pat_df["birthDate"] = pd.to_datetime(pat_df["birthDate"])
    pat_df["age"] = (now - pat_df["birthDate"]).astype("<m8[Y]")

    sum_age = int(pat_df["age"].sum())
    sum_pat = int(pat_df.shape[0])

    secure_age = paillier_addition(results, sum_age, "secure_age")
    secure_pat = paillier_addition(results, sum_pat, "secure_pat")

    results["analysis"]["secure_age"] = secure_age
    results["analysis"]["secure_pat"] = secure_pat

    # print updated results
    print("Updated results: {}".format(results))
    save_results(results, RESULT_PATH)
