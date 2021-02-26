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
            if not os.path.isdir('/opt/pht_results'):
                os.makedirs('/opt/pht_results')
                print('Created results directory')
            with open('/opt/pht_results/' + self.results, 'rb') as results_file:
                return pickle.load(file=results_file)
        except Exception:
            return {'analysis': {}, 'discovery': {}, 'exec': []}

    def save_results(self, results):
        """
        Saves the result file of the train
        :param results:
        :return:
        """
        try:
            with open('/opt/pht_results/' + self.results, 'wb') as results_file:
                return pickle.dump(results, results_file)
        except Exception:
            raise FileNotFoundError("Result file cannot be saved")

    def load_queries(self):
        """

        :return:
        """
        try:
            with open('/opt/pht_train/' + self.query, 'r') as queries:
                return json.load(queries)
        except Exception:
            return {'1': 'Station1',
                    '2': 'Station2',
                    '3': 'Station3'}

    def save_queries(self, query):
        """

        :param query:
        :return:
        """
        with open('/opt/pht_train/' + self.query, 'w') as queries:
            return json.dump(query, queries)

    def get_user_pk(self):
        try:
            with open('/opt/train_config.json', 'r') as train_conf:
                conf = json.load(train_conf)
                return conf['user_secure_add_pk']
        except Exception:
            return {'user_secure_add_pk': None}

    def secure_addition(self, local_result):
        result = self.load_results()
        try:
            prev_result = result['analysis']['task_a']
            print("Previous secure addition value {}".format(prev_result))
        except KeyError:
            print("Previous secure addition empty")
            prev_result = None
        try:
            n = self.key_manager.get_security_param(param="user_he_key")
        except Exception as e:
            print("Cannot load users he_key - use default n")
            print(e)
            n = 261846875800526071848173346729411495257

        return secure_addition(local_result, prev_result, int(n))