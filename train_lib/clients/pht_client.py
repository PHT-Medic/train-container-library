import requests
from io import BytesIO
import tarfile
import pika
import json
from typing import Union, List
from tarfile import TarFile
from dotenv import load_dotenv, find_dotenv
import os
import logging
import base64

LOGGER = logging.getLogger(__name__)


class PHTClient:
    """
    Client class for interacting with PHT services

    """

    def __init__(self, api_url: str, api_port: int = 5555, api_token: str = None, ampq_url: str = None,
                 vault_url: str = None, vault_token: str = None):
        """
        Set up connection parameters for the services (train api and rabbit mq)

        :param api_url: endpoint of the central TrainAPI
        :param api_port:
        :param ampq_url: ampq url containing username and password for connecting to rabbitmq
        :param api_token: token to be passed to the api
        :param vault_url: url of the vault api used for storing
        """
        self.api_url = api_url
        self.port = api_port
        self.token = api_token

        self.vault_url = vault_url
        self.api_headers = None
        self.vault_headers = None
        self._create_headers(api_token, vault_token)
        self.rmq_params = None
        if ampq_url:
            self.rmq_params = pika.URLParameters(ampq_url)

    def publish_message_rabbit_mq(self, message: Union[str, bytes, List[str], dict], exchange: str = "pht",
                                  exchange_type: str = "topic", routing_key: str = "pht"):
        """
        Publish a message to rabbit mq with the given message parameters

        :param message: the message to be published
        :param exchange: the identifier of the exchange
        :param exchange_type:
        :param routing_key:
        :return:
        """

        if self.rmq_params:
            connection = pika.BlockingConnection(self.rmq_params)
        else:
            LOGGER.info("No connection to rabbit mq specified, attempting connection on localhost")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.exchange_declare(exchange=exchange, exchange_type=exchange_type, durable=True)

        json_message = json.dumps(message).encode("utf-8")
        channel.basic_publish(exchange=exchange, routing_key=routing_key, body=json_message)

        LOGGER.info(" [x] Sent %r" % json_message)
        connection.close()

    def get_train_files_archive(self, train_id: str, token: str = None, client_id: str = None):
        """
        Get the tar archive containing files for building a train from the UI api

        :param train_id:
        :return:
        """
        endpoint = f"{train_id}/files/download"
        if not token:
            archive = self._get_tar_archive_from_stream(endpoint)
        else:
            archive = self._get_tar_archive_from_stream(endpoint, token=token, client_id=client_id)

        return archive

    def _get_tar_archive_from_stream(self, endpoint: str, params: dict = None,
                                     external_endpoint: bool = False, token: str = None,
                                     client_id: str = None) -> BytesIO:
        """
        Read a stream of tar data from the given endpoint and return an in memory BytesIO object containing the data

        :param endpoint: address relative to this instances api address
        :param params: dictionary containing additional parameters to be passed to the request
        :param external_endpoint: boolean parameter controlling whether the URL where the request is sent should built using
        the combination of api + endpoint or if the connection should be attempted on the raw endpoint string

        :return:
        """
        if external_endpoint:
            url = endpoint
        else:
            url = self.api_url + endpoint
        headers = self._create_api_headers(api_token=token, client_id=client_id)
        with requests.get(url, params=params, headers=headers, stream=True) as r:
            r.raise_for_status()
            file_obj = BytesIO()
            for chunk in r.iter_content():
                file_obj.write(chunk)
            file_obj.seek(0)

        return file_obj

    def get_user_pk(self, user_id):
        """
        Get the public key associated with the given user_id from vault storage

        :param user_id:
        :return: hex string containing an rsa public key
        """
        url = f"{self.vault_url}v1/user_pks/{user_id}"
        r = requests.get(url, headers=self.vault_headers)
        r.raise_for_status()
        data = r.json()["data"]["data"]
        return data["rsa_public_key"]

    def get_station_pk(self, station_id):
        """
        Get the rsa public of the station specified by station id from vault storage

        :param station_id: identifier of the station in vault
        :return: hex string containing an rsa public key
        """
        url = f"{self.vault_url}v1/station_pks/{station_id}"
        r = requests.get(url, headers=self.vault_headers)
        r.raise_for_status()
        public_key = r.json()["data"]["data"]["rsa_station_public_key"]
        return public_key

    def get_multiple_station_pks(self, station_ids: List) -> dict:
        station_pks = {}
        for id in station_ids:
            station_pks[id] = self.get_station_pk(id)
        return station_pks

    def post_route_to_vault(self, train_id, route, periodic=False):
        route = [str(_) for _ in route]
        vault_url = f"{self.vault_url}v1/kv-pht-routes/data/{train_id}"
        print(route)
        payload = {
            "options": {
                "cas": 0
            },
            "data": {
                "harborProjects": route,
                "repositorySuffix": str(train_id),
                "periodic": periodic
            }
        }
        r = requests.post(vault_url, headers=self.vault_headers, data=json.dumps(payload))
        r.raise_for_status()

    def _create_headers(self, api_token, vault_token):
        self.headers = self._create_api_headers(api_token)
        self.vault_headers = {"X-Vault-Token": vault_token}

    def _create_api_headers(self, api_token: str, client_id: str = "TRAIN_BUILDER"):
        auth_string = f"{client_id}:{api_token}"
        auth_string = base64.b64encode(auth_string.encode("utf-8")).decode()
        headers = {"Authorization": f"Basic {auth_string}"}
        return headers

