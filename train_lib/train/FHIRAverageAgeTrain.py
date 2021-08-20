import pandas as pd
import os
import json
import datetime


RESULTS_PATH = "/opt/pht_results/average_age.json"


def load_previous_data(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            average_age_dict = json.load(f)

        return average_age_dict

    else:
        return None


def age_from_dob(dob):
    today = datetime.date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def calculate_new_average(average_age_dict, data_path, results_path):
    # load the data and ensure that birthdate is a datetime column
    data = pd.read_csv(data_path)
    data["birthDate"] = pd.to_datetime(data["birthDate"])

    ages = data["birthDate"].apply(lambda x: age_from_dob(x))

    local_average = ages.mean()

    # previous results exist load them otherwise create a new dictionary containing the results
    if average_age_dict:
        prev_average = average_age_dict["average_age"]
        new_average = (prev_average + local_average) / 2 if prev_average else local_average
        average_age_dict["average_age"] = new_average
    else:
        new_average = local_average
        average_age_dict = {"average_age": new_average}

    print(average_age_dict)

    # store the updated results
    with open(results_path, "w") as f:
        json.dump(average_age_dict, fp=f, indent=2)


def main():
    data_path = os.getenv("TRAIN_DATA_PATH", "/opt/train_data/patients.csv")
    print(f"Loading data at {data_path}")
    prev_results = load_previous_data(RESULTS_PATH)
    calculate_new_average(prev_results, data_path, RESULTS_PATH)


if __name__ == '__main__':
    main()
