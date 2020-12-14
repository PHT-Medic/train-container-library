import requests
from io import BytesIO
import tarfile
import pika
import json
from typing import Union, List
from tarfile import TarFile


UI_TRAIN_API = "http://pht-ui.personalhealthtrain.de/api/pht/trains/"


class PHTClient:
    """
    Client class for interacting with PHT services

    """

    def __init__(self, api_url: str, port: int = 5555,
                 ampq_url: str = None,
                 token: str = None):
        """
        Set up connection parameters for the services (train api and rabbit mq)

        :param api_url: endpoint of the central TrainAPI
        :param port:
        :param ampq_url: ampq url containing username and password for connecting to rabbitmq
        :param token: token to be passed to the api
        """
        self.api_url = api_url
        self.port = port
        self.token = token
        self.headers = None
        if token:
            self._create_headers(token)
        self.rmq_params = None
        if ampq_url:
            self.rmq_params = pika.URLParameters(ampq_url)

    def publish_message_rabbit_mq(self, message: Union[str, bytes, List[str]], exchange: str = "message",
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
            print("No connection to rabbit mq specified, attempting connection on localhost")
            connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.exchange_declare(exchange=exchange, exchange_type=exchange_type)

        json_message = json.dumps(message)
        channel.basic_publish(exchange=exchange, routing_key=routing_key, body=json_message)

        print(" [x] Sent %r" % json_message)
        connection.close()

    def get_train_files_archive(self, train_id: str):
        endpoint = train_id + "/tar"
        archive = self._get_tar_archive_from_stream(endpoint)
        return archive

    def _get_tar_archive_from_stream(self, endpoint: str, params: dict = None,
                                     external_endpoint: bool = False) -> TarFile:
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
        with requests.get(url, params=params, headers=self.headers, stream=True) as r:
            r.raise_for_status()
            file_obj = BytesIO()
            for chunk in r.iter_content():
                file_obj.write(chunk)
            file_obj.seek(0)
        tar = tarfile.open(mode="r", fileobj=file_obj)
        return tar

    def _create_headers(self, token, **kwargs) -> dict:
        pass


if __name__ == '__main__':
    ampq_url = "amqp://pht:start123@193.196.20.19:5672/"
    pht_client = PHTClient(UI_TRAIN_API, ampq_url=ampq_url)
    tar_url = 'https://pypi.python.org/packages/source/x/xlrd/xlrd-0.9.4.tar.gz'
    # archive = pht_client._get_tar_archive_from_stream(tar_url, external_endpoint=True)
    # print(archive)
    pht_client.publish_message_rabbit_mq("Client Test", )
