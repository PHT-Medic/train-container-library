import pprint
from typing import List, Union
from fhir.resources.domainresource import DomainResource
from train_lib.fhir import PHTFhirClient
from fhir.resources.fhirtypes import AbstractType
from fhir.resources.bundle import Bundle, BundleEntry, BundleEntryRequest


class FhirResourceGenerator:

    def __init__(self, n: int, resources: List[DomainResource] = None,
                 resource_type: DomainResource = None,
                 fhir_server: str = None, fhir_user: str = None, fhir_pw: str = None, fhir_token: str = None):
        self.fhir_token = fhir_token
        self.fhir_pw = fhir_pw
        self.fhir_user = fhir_user
        self.fhir_server = fhir_server
        self.n = n
        self.resource_type = resource_type
        self.resources = resources

        if self.fhir_server:
            self.fhir_client = PHTFhirClient(server_url=self.fhir_server, username=self.fhir_user,
                                             password=self.fhir_pw, token=self.fhir_token)

    def generate(self, upload: bool = False):
        pass

    def make_bundle(self) -> Bundle:
        entries = self._generate_bundle_entries()
        bundle_data = {
            "type": "transaction",
            "entry": entries
        }
        bundle = Bundle(**bundle_data)
        pprint.pprint(bundle.json())

        return bundle

    def _generate_bundle_entries(self):
        entries = []
        for resource in self.resources:
            bundle_entry_dict = {
                "resource": resource,
                "request": BundleEntryRequest(**{"method": "POST", "url": self.resource_type.get_resource_type()})
            }
            entry = BundleEntry(**bundle_entry_dict)
            entries.append(entry)
        return entries

    def display_schema(self):
        pprint.pprint(self.resource_type.schema())
