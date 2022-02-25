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
    def __init__(self, model=None, results=None, query=None):
        # Model and results encoded with Pickle
        self.encoded_model = model
        self.results = results
        self.query = query

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

    def _flatten(self, l):
        return [item for sublist in l for item in sublist]

    def load_sequences(self, patients, class_labels):
        _RESIDUES = [
            'A', 'R', 'N', 'D', 'C', 'E', 'Q', 'G', 'H', 'I', 'L', 'K', 'M', 'F', 'P', 'S', 'T', 'W', 'Y', 'V', '-'
        ]

        _RESIDUE_ENCODING = {
            residue: (index * [0]) + [1] + (len(_RESIDUES) - index - 1) * [0] for index, residue in enumerate(_RESIDUES)
        }

        x = []
        y = []

        feature_space_dimension = None

        for index, row in patients.iterrows():
            label = 'CXCR4' if len(row["observedAllele"]) > 4 else row["observedAllele"]
            seq = row["observedSeq"]
            seq_encoded = self._flatten(_RESIDUE_ENCODING[residue] for residue in seq)
            seq_encoded_len = len(seq_encoded)

            if feature_space_dimension is None:
                feature_space_dimension = seq_encoded_len
            elif feature_space_dimension != seq_encoded_len:
                raise ValueError('Inconsistent feature length: {} vs. {}'.format(
                    feature_space_dimension, seq_encoded_len))
            x.append(seq_encoded)
            y.append(class_labels[label])
        return x, y

    def plot_results(self, results):
        # figure 1 sample sizes and test size
        num_stations = len(results.items()) + 1  # for all samples

        # data to plot
        train_sam = []
        test_sam = []
        acc = []

        for i in results.items():
            test_sam.append(i[1]['test_samples'])
            train_sam.append(i[1]['training_samples'])
            acc.append(i[1]['acc_total'])

        # append total column
        train_sam.append(sum(train_sam))
        test_sam.append(sum(test_sam))

        # create plot
        plt.figure(1)
        index = np.arange(num_stations)
        bar_width = 0.5
        opacity = 0.8

        p1 = plt.bar(index, train_sam, bar_width, alpha=opacity, color='deepskyblue', label='train')
        p2 = plt.bar(index, test_sam, bar_width, bottom=train_sam, alpha=opacity, color='coral', label='test')

        plt.xlabel('Stations')
        plt.ylabel('Samples')
        plt.title('Samples per Station')

        station_labels = list(range(1, len(results) + 1))
        station_labels = [str(x) for x in station_labels]
        station_labels.append('All')

        # print(p1, p2)
        # print(p1[0], p2[0])

        plt.xticks(index, station_labels)
        plt.legend((p1[0], p2[0]), ('train', 'test'))
        plt.legend()

        plt.tight_layout()

        if not os.path.isdir("/opt/pht_results/"):
            os.mkdir("/opt/pht_results/")

        plt.savefig('/opt/pht_results/analysis_1.png')
        plt.show()

        # figure 2 acc over stations
        plt.figure(2)
        index = np.arange(num_stations)
        p3 = plt.plot(acc, 'ro')

        plt.xlabel('Stations')
        plt.ylabel('Accuracy [%]')
        plt.title('Accuracy over stations')

        station_labels = list(range(1, len(results) + 1))
        station_labels = [str(x) for x in station_labels]

        plt.xticks(np.arange(num_stations - 1), station_labels)
        plt.legend('Accuracy')
        plt.legend()

        plt.tight_layout()
        plt.savefig('/opt/pht_results/analysis_2.png')
        plt.show()
