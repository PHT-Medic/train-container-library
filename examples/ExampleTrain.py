import json
import pickle
import os

from train_lib.security.HomomorphicAddition import secure_addition
from train_lib.security.KeyManager import KeyManager


class Train:
    def __init__(self,  results=None, query=None):
        """

        :param results:
        :param query:
        """
        self.results = results
        self.query = query
        self.key_manager = KeyManager(train_config='/opt/train_config.json')

    def load_results(self):
        """
        If a result file exists, loads the results. Otherwise will return empty results.
        :return:
        """
        try:
            with open('/opt/pht_results/' + self.results, 'rb') as results_file:
                return pickle.load(file=results_file)
        except Exception:
            return {'analysis': {}, 'discovery': {}}

    def save_results(self, results):
        """
        Saves the result file of the train
        :param results:
        :return:
        """
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
                        "query_lst": [["link", "NF-CORE-Station1"],
                                      ["link", "NF-CORE-Station2"],
                                      ["link", "NF-CORE-Station3"]],
                        "output_param_list": ["id", "gender", "birthDate"],
                        "media": "False"
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

    def secure_addition_avg(self, total_age, num_pat):
        result = self.load_results()
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

        return result

