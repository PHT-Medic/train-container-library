import json
import pickle
import os
import scipy.io as sio
import pandas as pd
import shutil
from glob import glob
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

COLOR_DICT = {
    'acc': '#e41a1c',
    'sens': '#377eb8',
    'loss': '#ffff33',
    'wacc': '',
    'auc': '#4daf4a',
    'spec': '',
    'f1': '#984ea3',
    'train_loss': '#ff7f00',
}


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
            return {'1': 'station_1',
                    '2': 'station_2',
                    '3': 'station_3'}

    def save_queries(self, query):
        """

        :param query:
        :return:
        """
        with open('/opt/pht_train/' + self.query, 'w') as queries:
            return json.dump(query, queries)

    def discovery(self, patients, results):
        # discovery
        gender = {'female': 1, 'male': 0, 'unknown': 999}
        patients.gender = [gender[item] for item in patients.gender]
        patients.astype({"gender": 'int'})

        #print(patients.describe())

        discovery = {'total_samples': len(patients),
                     'MEL': patients[patients.note == 'MEL'].shape[0],
                     'NV': patients[patients.note == 'NV'].shape[0],
                     'BCC': patients[patients.note == 'BCC'].shape[0],
                     'AK': patients[patients.note == 'AK'].shape[0],
                     'BKL': patients[patients.note == 'BKL'].shape[0],
                     'DF': patients[patients.note == 'DF'].shape[0],
                     'VASC': patients[patients.note == 'VASC'].shape[0],
                     'SCC': patients[patients.note == 'SCC'].shape[0],
                     'UNK': patients[patients.note == 'UNK'].shape[0]
                     }
        results['discovery']['discovery_exec_' + str(len(results['discovery']) + 1)] = discovery
        print(results)
        return results

    def plot_discovery_results(self, results):
        print(results)
        num_stations = len(results.items()) + 1  # for all samples

        # data to plot
        class_0 = []
        class_1 = []
        class_2 = []
        class_3 = []
        class_4 = []
        class_5 = []
        class_6 = []
        class_7 = []
        class_8 = []

        stat_samples = []

        for i in results.items():
            stat_samples.append(i[1]['total_samples'])
            class_0.append(i[1]['MEL'])
            class_1.append(i[1]['NV'])
            class_2.append(i[1]['BCC'])
            class_3.append(i[1]['AK'])
            class_4.append(i[1]['BKL'])
            class_5.append(i[1]['DF'])
            class_6.append(i[1]['VASC'])
            class_7.append(i[1]['SCC'])
            class_8.append(i[1]['UNK'])

        # append total column
        class_0.append(sum(class_0))
        class_1.append(sum(class_1))
        class_2.append(sum(class_2))
        class_3.append(sum(class_3))
        class_4.append(sum(class_4))
        class_5.append(sum(class_5))
        class_6.append(sum(class_6))
        class_7.append(sum(class_7))
        class_8.append(sum(class_8))

        # create plot
        fig, ax = plt.subplots()
        index = np.arange(num_stations)
        bar_width = 0.5
        opacity = 0.8

        p1 = plt.bar(index, class_0, bar_width, alpha=opacity, label='MEL')
        p2 = plt.bar(index, class_1, bar_width, bottom=class_0, alpha=opacity, label='NV')
        p3 = plt.bar(index, class_2, bar_width, bottom=class_1, alpha=opacity, label='BCC')
        p4 = plt.bar(index, class_3, bar_width, bottom=class_2, alpha=opacity, label='AK')
        p5 = plt.bar(index, class_4, bar_width, bottom=class_3, alpha=opacity, label='BKL')
        p6 = plt.bar(index, class_5, bar_width, bottom=class_4, alpha=opacity, label='DF')
        p7 = plt.bar(index, class_6, bar_width, bottom=class_5, alpha=opacity, label='VASC')
        p8 = plt.bar(index, class_7, bar_width, bottom=class_6, alpha=opacity, label='SCC')
        p9 = plt.bar(index, class_8, bar_width, bottom=class_7, alpha=opacity, label='UNK')

        plt.xlabel('Stations')
        plt.ylabel('Samples')
        plt.title('Samples at different Station')

        station_labels = list(range(1, len(results) + 1))
        station_labels = [str(x) for x in station_labels]
        station_labels.append('All')

        plt.xticks(index, station_labels)
        plt.legend((p1[0], p2[0], p3[0], p4[0], p5[0], p6[0], p7[0], p8[0], p9[0]),
                   ('Class: MEL', 'Class: NV', 'Class: BCC', 'Class: AK', 'Class: BKL', 'Class: DF',
                    'Class: VASC', 'Class: SCC', 'Class: UNK'))

        plt.tight_layout()
        plt.savefig('/opt/pht_results/discovery.png')

    def station_to_dict(self, station_path):
        # TODO: Assumes epochs of first CV! If first CV only one with that amount of epochs ignores complete rest!
        pathlist = glob(station_path + '/**progression_valInd.mat')
        # print(list(pathlist))
        paths = []
        station_dict = {}
        cv_counts = 0
        for path in pathlist:
            mat = sio.loadmat(path)
            cv_counts += 1
            for k, v in mat.items():
                if k in COLOR_DICT.keys():
                    if k not in station_dict.keys():
                        station_dict[k] = v.copy()
                        station_dict[f'{k}_min'] = v.copy()
                        station_dict[f'{k}_max'] = v.copy()
                    else:
                        try:
                            station_dict[k] += v.copy()
                        except Exception as e:
                            print(e)
                            cv_counts -= 1
                            break

                        station_dict[f'{k}_min'] = np.minimum(station_dict[f'{k}_min'], v.copy())
                        station_dict[f'{k}_max'] = np.maximum(station_dict[f'{k}_max'], v.copy())

                else:
                    if not k in station_dict.keys():
                        station_dict[k] = v
        for k in station_dict.keys():
            if k in COLOR_DICT.keys():
                station_dict[k] /= cv_counts

        _st = Path(pathlist[0]).parents[1].name
        station_dict['station'] = _st[0].upper() + _st[1:]

        return station_dict

    def make_plot_dict(self, station_path, plot_params, std=False, num_stations=3):
        '''
        This helper function encapsulates the generation of a plot dictionary containing all information relevant for the
        plot and improving the possibility to

        Args:
            station_path: Path or list of paths to station results
            plot_params: parameters which to be plotted given as list
            std: Add range of all CVs to the plot
            num_stations: Number of stations in the end (extends plot)

        Returns: plot dictionary for a given route

        '''

        if not isinstance(station_path, list):
            station_path = [station_path]

        plot_dict = {
            'num_stations': len(station_path),
            'stations': [],
            'station_epochs': [],
            'params': {},
            'plot_epochs': np.array([])
        }
        for p in plot_params:
            plot_dict['params'][p] = np.array([])
            if std:
                plot_dict['params'][f'{p}_min'] = np.array([])
                plot_dict['params'][f'{p}_max'] = np.array([])

        for station in station_path:
            m = self.station_to_dict(station)
            plot_dict['station_epochs'].append(m['step_num'][0][-1])
            plot_dict['stations'].append(m['station'])
            if not plot_dict['plot_epochs'].size == 0:
                plot_dict['plot_epochs'] = np.append(plot_dict['plot_epochs'], plot_dict['plot_epochs'][-1] + m['step_num'][0])
            else:
                plot_dict['plot_epochs'] = np.append(plot_dict['plot_epochs'], m['step_num'][0])
            for k in plot_dict['params'].keys():
                if k in ['acc', 'f1', 'train_loss', 'loss']:
                    plot_dict['params'][k] = np.append(plot_dict['params'][k], m[k][0])
                    if std:
                        plot_dict['params'][f'{k}_min'] = np.append(plot_dict['params'][f'{k}_min'], m[f'{k}_min'][0])
                        plot_dict['params'][f'{k}_max'] = np.append(plot_dict['params'][f'{k}_max'], m[f'{k}_max'][0])
                elif k in ['sens', 'auc']:
                    plot_dict['params'][k] = np.append(plot_dict['params'][k], np.mean(m[k], axis=1))
        return plot_dict

    def central_plot(self, routes, plot_params, save_path, smoothing_factor=None, std=False, save=False, num_stations=1):
        smoothing = False
        if smoothing_factor:
            smoothing_factor = np.ones(len(plot_params)) * smoothing_factor if isinstance(smoothing_factor,float) \
                else np.array(smoothing_factor)
            smoothing = True
        else:
            smoothing_factor = np.ones(len(plot_params))

        nrows = 1
        ncols = 1
        fig, axs = plt.subplots(nrows=nrows, ncols=ncols, sharex='row', sharey='all', squeeze=False, figsize=(6, 5))

        for i, ax in enumerate(fig.axes):
            plot_dict = self.make_plot_dict(routes[i], plot_params, std=std)
            extend_plot = num_stations - plot_dict['num_stations'] if num_stations >= plot_dict['num_stations'] else plot_dict['num_stations']

            ax.set_xlim(right=(plot_dict['num_stations']+extend_plot)*60)
            ax.set_ylim(bottom=0.2, top=0.9)

            min_val = np.inf
            max_val = -np.inf
            plotting = {item: value for (item, value) in plot_dict['params'].items() if item in plot_params}
            # for (k, v), s in zip(plot_dict['params'].items(), smoothing_factor):
            for (k, v), s in zip(plotting.items(), smoothing_factor):
                min_val = np.min(v) if np.min(v) < min_val else min_val
                max_val = np.max(v) if np.max(v) > max_val else max_val

                if k in ['acc', 'sens', 'f1']:
                    measure = np.max
                else:
                    measure = np.min

                print(f'Measure "{k}": best overall value -> {measure(v)}')
                print(f'Measure "{k}": last value -> {v[-1]}')

                ax.plot(plot_dict['plot_epochs'], v,
                        color=COLOR_DICT[k],
                        label=k)
                if smoothing:
                    ax.plot(plot_dict['plot_epochs'], np.array(pd.Series(v).ewm(alpha=s).mean().to_numpy()),
                            color=COLOR_DICT[k],
                            label=f'{k}_smoothed',
                            alpha=.7)

                if std:
                    ax.fill_between(plot_dict['plot_epochs'], plot_dict['params'][f'{k}_max'], plot_dict['params'][f'{k}_min'],
                                    alpha=.2, color=COLOR_DICT[k])

            div = 0
            for station in plot_dict['station_epochs'][:-1]:
                div += station
                ax.axvline(div, linestyle='--')

            ax.legend(loc='lower right', framealpha=0.5, title='Metrics')
            if i%ncols == 0:
                ax.set_ylabel('Result')

            ax.set_xlabel('Epochs')
            ax.set_title('Evaluation of Efficientnet-b6 on ISIC 2019')
            handles, labels = ax.get_legend_handles_labels()

        plt.subplots_adjust(left=0.15, bottom=0.2, right=0.95)

        if save:
            plt.savefig(save_path)
        else:
            plt.show()

    def plot_stations(self, routes, plot_params, save_path, smoothing_factor=None, std=False, save=False, num_stations=3):
        smoothing = False
        if smoothing_factor:
            smoothing_factor = np.ones(len(plot_params)) * smoothing_factor if isinstance(smoothing_factor,float) \
                else np.array(smoothing_factor)
            smoothing = True
        else:
            smoothing_factor = np.ones(len(plot_params))

        nrows = 1
        ncols = 1
        fig, axs = plt.subplots(nrows=nrows, ncols=ncols, sharex='row', sharey='all', squeeze=True, figsize=(6, 5))

        for i, ax in enumerate(fig.axes):
            plot_dict = self.make_plot_dict(routes[i], plot_params, std=std)
            extend_plot = num_stations - plot_dict['num_stations'] if num_stations >= plot_dict['num_stations'] else plot_dict['num_stations']

            ax.set_xlim(right=(plot_dict['num_stations']+extend_plot)*20)
            ax.set_ylim(bottom=0.2, top=.9)

            min_val = np.inf
            max_val = -np.inf
            plotting = {item: value for (item, value) in plot_dict['params'].items() if item in plot_params}
            # for (k, v), s in zip(plot_dict['params'].items(), smoothing_factor):
            for (k, v), s in zip(plotting.items(), smoothing_factor):
                min_val = np.min(v) if np.min(v) < min_val else min_val
                max_val = np.max(v) if np.max(v) > max_val else max_val

                if k in ['acc', 'sens', 'f1']:
                    measure = np.max
                else:
                    measure = np.min

                print(f'Measure "{k}": best overall value -> {measure(v)}')
                print(f'Measure "{k}": last value -> {v[-1]}')

                ax.plot(plot_dict['plot_epochs'], v,
                        color=COLOR_DICT[k],
                        label=k)
                if smoothing:
                    ax.plot(plot_dict['plot_epochs'], np.array(pd.Series(v).ewm(alpha=s).mean().to_numpy()),
                            color=COLOR_DICT[k],
                            label=f'{k}_smoothed',
                            alpha=.7)

                if std:
                    ax.fill_between(plot_dict['plot_epochs'], plot_dict['params'][f'{k}_max'], plot_dict['params'][f'{k}_min'],
                                    alpha=.2, color=COLOR_DICT[k])

            div = 0
            for station in plot_dict['station_epochs'][:-1]:
                div += station
                ax.axvline(div, linestyle='--')

            ax.legend(loc='lower right', framealpha=0.5, title='Metrics')
            if i%ncols == 0:
                ax.set_ylabel('Result')
            ax.set_xlabel('Epochs')
            for j, st in enumerate(['Station 1', 'Station 2', 'Station 3']):
                ax.text(6+(20*j), 0.95, st, transform=ax.get_xaxis_transform())

            ax.set_title('Evaluation of Efficientnet-b6 on ISIC 2019')
            handles, labels = ax.get_legend_handles_labels()

        plt.subplots_adjust(left=0.15, bottom=0.2, right=0.95)

        if save:
            plt.savefig(save_path)
        else:
            plt.show()

    def create_label_file(self, patients_df, path_labels, station):
        patients_df.patientId = patients_df.patientId.str.replace('-', '_')
        y = pd.get_dummies(patients_df.note)
        cols = ["MEL", "NV", "BCC", "AK", "BKL", "DF", "VASC", "SCC"]
        new_index_df = y[cols].astype('float')
        new_index_df["UNK"] = 0.0
        new_index_df.insert(0, "image", patients_df.patientId)
        print(new_index_df.describe())
        new_index_df.to_csv(path_labels + 's_' + str(station) + '_labels.csv', index=False)

        return new_index_df

    def move_file(self, src_file, dst_file):
        shutil.move(src=src_file, dst=dst_file)
        return True

    def copy_file(self, src_file, dst_file):
        shutil.copy(src=src_file, dst=dst_file)
        return True

    def create_stat_res_dirs(self, station):
        os.mkdir('/opt/pht_results/res_' + str(station))
        return True

    def locate_mat_files(self, exec_path):
        return glob(exec_path + '/**/*.mat')

    def find_best_cv(self, performance):
        res = {}
        max_val = 0
        for key, nested in performance.items():
            if nested['BestF1'] > max_val:
                max_val = nested['BestF1']
                res[key] = max_val
        print('Best CV performance in fold {} (index 0-4)'.format(list(res)[-1]))
        return list(res)[-1]

    def clean_up(self, exec_dir):
        os.rmdir(exec_dir)
        return True

