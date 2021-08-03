from resource_generator import FhirResourceGenerator
from typing import Union, Tuple, List
from fhir.resources.patient import Patient
from fhir.resources.humanname import HumanName
from datetime import datetime, timedelta
from pendulum import DateTime
import pendulum
import pandas as pd

from fhir.resources import fhirtypes
from pprint import pprint
import random


class PatientGenerator(FhirResourceGenerator):

    def __init__(self, n: int,
                 age_range: Tuple[DateTime, DateTime] = None,
                 gender_distribution: Tuple[float, float, float, float] = None):
        super().__init__(n, resource_type="Patient")
        self.age_range = age_range
        self.gender_distribution = gender_distribution
        self.birthdate_range = None

    def generate(self) -> List[Patient]:
        patients = []
        names = self._generate_patient_names(self.n)
        for i in range(self.n):
            patient_dict = self._generate_patient_data(name=names[i])
            patients.append(Patient(**patient_dict))
        return patients

    def _generate_patient_data(self, name: Tuple[str, str]) -> dict:
        gender = random.choices(
            ["male", "female", "other", "unknown"],
            weights=self.gender_distribution if self.gender_distribution else [0.45, 0.45, 0.1, 0.0], k=1)[0]

        name = HumanName(**{"family": name[1], "given": [name[0]]})

        birthdate = self._generate_birthdate()
        patient_dict = {
            "gender": gender,
            "name": [name],
            "birthDate": birthdate
        }

        return patient_dict

    @staticmethod
    def _generate_patient_names(n: int):
        with open("data/first_names.txt", "rb") as fnf:
            first_name_list = [fn.decode().strip().capitalize() for fn in fnf.readlines()]

        with open("data/last_names.txt", "rb") as lnf:
            last_name_list = [ln.decode().strip().capitalize() for ln in lnf.readlines()]

        first_names = random.choices(first_name_list, k=n)
        last_names = random.choices(last_name_list, k=n)
        names = list(zip(first_names, last_names))

        return names

    def _generate_birthdate(self):

        if not self.birthdate_range:
            if self.age_range:
                youngest = self.age_range[0].to_date_string()
                oldest = self.age_range[1].to_date_string()
            else:
                # generate random birthdates from 18-101 years old
                now = pendulum.now()
                youngest = pd.to_datetime((now - pendulum.duration(years=18)).to_date_string())
                oldest = pd.to_datetime((now - pendulum.duration(years=101)).to_date_string())

            self.birthdate_range = pd.date_range(oldest, youngest, freq="D").strftime('%Y-%m-%d').tolist()

        birthdate = random.choice(self.birthdate_range)
        return birthdate


if __name__ == '__main__':
    # pprint(Patient.schema()["properties"])
    pg = PatientGenerator(n=10)
    print(pg.generate())
