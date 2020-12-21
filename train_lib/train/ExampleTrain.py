import json
import pickle
import os


class Train:
    def __init__(self,  results=None, query=None):
        """

        :param results:
        :param query:
        """
        self.results = results
        self.query = query

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
            with open('/opt/pht_results/' + self.query, 'r') as query:
                data = json.load(query)

            query_lst = data['query_lst']
            output_list = data['output_param_list']
            media = data["media"]
            return query_lst, output_list, media
        except Exception:
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
        with open('/opt/pht_results/' + self.query, 'w') as queries:
            return json.dump(query_file, queries, indent=4)

