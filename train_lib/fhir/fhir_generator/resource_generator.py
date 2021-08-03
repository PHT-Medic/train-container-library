from uuid import uuid4
from typing import List
from fhir.resources.fhirabstractmodel import FHIRAbstractModel


class FhirResourceGenerator:

    def __init__(self, n: int, resources: List[FHIRAbstractModel] = None, resource_type: str = None):
        self.n = n
        self.resource_type = resource_type
        self.resources: List[FHIRAbstractModel] = resources

    def generate(self):
        pass

    def make_bundle(self):
        pass
