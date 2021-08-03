from uuid import uuid4
from typing import List
from fhir.resources.fhirabstractmodel import FHIRAbstractModel
from train_lib.fhir import PHTFhirClient


class FhirResourceGenerator:

    def __init__(self, n: int, resources: List[FHIRAbstractModel] = None, resource_type: str = None,
                 fhir_server: str = None, fhir_user: str = None, fhir_pw: str = None, fhir_token: str = None):
        self.fhir_token = fhir_token
        self.fhir_pw = fhir_pw
        self.fhir_user = fhir_user
        self.fhir_server = fhir_server
        self.n = n
        self.resource_type = resource_type
        self.resources: List[FHIRAbstractModel] = resources

        if self.fhir_server:
            self.fhir_client = PHTFhirClient(server_url=self.fhir_server, username=self.fhir_user,
                                             password=self.fhir_pw, token=self.fhir_token)

    def generate(self, upload: bool = False):
        pass

    def make_bundle(self):
        pass
