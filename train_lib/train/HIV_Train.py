import pickle
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
import os
import numpy as np
import matplotlib.pyplot as plt
import json

from train_lib.security.HomomorphicAddition import secure_addition
from train_lib.security.KeyManager import KeyManager

class Train:
    def __init__(self, model=None, data_path=None, results=None, query=None):
        # Model and results encoded with Pickle
        self.encoded_model = model
        self.data_path = data_path
        self.results = results
        self.query = query
        #self.key_manager = KeyManager(train_config='/opt/train_config.json')

    def _load_model(self):
        with open(self.encoded_model, 'rb') as model_file:
            return pickle.load(file=model_file)

    def _save_model(self, model):
        with open(self.encoded_model, 'wb') as model_file:
            pickle.dump(model, model_file)

    def _load_results(self):
        try:
            with open('/opt/pht_results/' + self.results, 'rb') as results_file:
                return pickle.load(file=results_file)
        except:
            return {'analysis': {}, 'discovery': {}}

    def _save_results(self, results):
        try:
            if not os.path.isdir('/opt/pht_results'):
                os.makedirs('/opt/pht_results')
                print('Created results directory')
            with open('/opt/pht_results/' + self.results, 'wb') as results_file:
                return pickle.dump(results, results_file)
        except Exception:
            raise FileNotFoundError("Result file cannot be saved")

    def load_queries(self):
        try:
            with open('/opt/' + self.query, 'r') as query:
                data = json.load(query)

            query_lst = data['query_lst']
            output_list = data['output_param_list']
            media = data["media"]
            return query_lst, output_list, media
        except Exception as e:
            print(e)
            data = {
                        "query_lst": [["link", "HIVdemo_LMU,HIVdemo_TUM,HIVdemo_UKT", "birthdate", "le1970-01-01"],
                                        ["link", "HIVdemo_LMU,HIVdemo_TUM,HIVdemo_UKT", "birthdate", "gt1970-01-01", "birthdate", "le2000-01-01"],
                                        ["link", "HIVdemo_LMU,HIVdemo_TUM,HIVdemo_UKT", "birthdate", "gt2000-01-01"]],
                        "output_param_list": ["id", "gender", "birthDate", "link", "observedAllele", "observedSeq"],
                        "media": "MolSeq"
                    }
            print("Error in query - use hardcoded query!")
            query_lst = data['query_lst']
            output_list = data['output_param_list']
            media = data["media"]
            return query_lst, output_list, media

    def save_queries(self, query_file):
        """
        :param query:
        :return:
        """
        with open('/opt/' + self.query, 'w') as queries:
            return json.dump(query_file, queries, indent=4)

    """
    def secure_addition_avg(self, total_age, num_pat):
        result = self._load_results()
        try:
            prev_num_pat = result['discovery']['secure_num_pat']
            prev_total_age = result['discovery']['secure_total_age']

            print("Previous secure addition value total number patients:\n"
                  "{}\nand total age\n{}".format(prev_num_pat, prev_total_age))
        except KeyError:
            print("Previous secure addition empty")
            prev_num_pat = None
            prev_total_age = None
        try:
            n = self.key_manager.get_security_param(param="user_he_key")
            print('Using he key from user in train config {}'.format(n))
        except Exception as e:
            print(e)
            print("Errors: no users HE key - use default n")

            n = 26186875800526071848173346729411495257
        result['discovery']['secure_num_pat'] = secure_addition(num_pat, prev_num_pat, int(n))
        result['discovery']['secure_total_age'] = secure_addition(total_age, prev_total_age, int(n))

        return result"""
