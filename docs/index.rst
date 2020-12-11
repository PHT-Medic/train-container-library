.. PHT train container library documentation master file, created by
   sphinx-quickstart on Thu Nov 26 08:53:05 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PHT train container library's documentation!
=======================================================

This library provides different components required for executing and securing
docker images (Trains) in the Personal Health Train (PHT) architecture.

   TODO add links to paper and station

The following packages are intended either for use inside of Apache Airflow dags utilized by a
station to interact with Trains or to provide functionality inside of a running Train container.

.. toctree::
   :maxdepth: 2
   :caption: Packages

   modules/security
   modules/dockerUtil




Installation
------------
#. Clone the `repository <https://gitlab.com/PersonalHealthTrain/implementations/germanmii/difuture/train-container-library>`_
   ::

      git clone https://gitlab.com/PersonalHealthTrain/implementations/germanmii/difuture/train-container-library



#. Navigate into the created directory and install the package using ``pip`` package manager.
   ::

      cd train-container-library
      pip install .


Usage
-----
After installation the packages are available for import i.e::

   from train_lib.docker_ops.docker_util import extract_train_config

This function can be used to extract the configuration file from a train image












Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

