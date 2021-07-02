import dotenv
import os
import pandas as pd
import pickle

from pathlib import Path
from fhirpy import AsyncFHIRClient
from fhirpy.base.searchset import Raw

import asyncio


async def genome_query(query):
    dotenv.load_dotenv()

    FHIR_ADDRESS = os.getenv('FHIR_ADDRESS')
    FHIR_TOKEN = os.getenv('FHIR_TOKEN')

    # Create an instance
    client = AsyncFHIRClient(
        FHIR_ADDRESS,
        authorization=FHIR_TOKEN,
    )

    media_dat = []
    patients_data, media_data = [], []

    # Search for patients
    resources_p = client.resources('Patient')  # Return lazy search set
    resources_p = resources_p.search(link__other='NF-CORE-' + query)
    patients = await resources_p.fetch_all()  # Returns list of AsyncFHIRResource

    for entry in patients:
        patient = entry.serialize()
        id = patient['id']
        name_family = patient['name'][0]['family']
        name_given = patient['name'][0]['given'][0]
        gender = patient['gender']
        birthDate = patient['birthDate']
        patients_data.append([id, name_family, name_given, gender, birthDate])

    patients_df = pd.DataFrame(patients_data,
                               columns=["patientId", "name_family", "name_given", "gender", "birthDate"])

    for id in patients_data:
        resources_m = client.resources('Media')
        resources_m = resources_m.search(subject__reference='Patient/' + id[0])
        media = await resources_m.fetch()

        for entry in media:
            media = entry.serialize()
            id = media['id'].split('-')[0]
            reference = media['subject']['reference']
            url_path = media['content']['url']
            media_data.append([id, reference, url_path])

        media_df = pd.DataFrame(media_data, columns=["patientId", "reference", "paths"])

    final_df = pd.merge(patients_df, media_df, on="patientId", how='inner')

    final_df[['path_1', 'path_2']] = final_df.paths.str.split(",", expand=True)
    final_df = final_df.drop(['paths'], axis=1)
    final_df['root_path'] = final_df['path_1'].apply(lambda x: str(Path(x).parents[2]))

    return final_df


async def isic_query(query):
    dotenv.load_dotenv()

    FHIR_ADDRESS = os.getenv('FHIR_ADDRESS')
    FHIR_TOKEN = os.getenv('FHIR_TOKEN')

    # Create an instance
    client = AsyncFHIRClient(
        FHIR_ADDRESS,
        authorization=FHIR_TOKEN,
    )

    patients_data, media_data = [], []

    # Search for patients
    resources_p = client.resources('Patient')  # Return lazy search set
    resources_p = resources_p.search(link__other='ISIC-'+str(query))
    patients = await resources_p.fetch_all()  # Returns list of AsyncFHIRResource

    for entry in patients:
        patient = entry.serialize()
        id = patient['id']
        gender = patient['gender']
        birthDate = patient['birthDate']
        patients_data.append([id, gender, birthDate])

    #print(len(patients_data))

    patients_df = pd.DataFrame(patients_data, columns=["patientId", "gender", "birthDate"])

    for id in patients_data:
        resources_m = client.resources('Media')
        resources_m = resources_m.search(subject__reference='Patient/' + id[0])
        medias = await resources_m.fetch_all()

        for entry in medias:
            media = entry.serialize()
            id = media['id']
            reference = media['subject']['reference']
            try:
                bodySite = media['bodySite']['text']
            except:
                bodySite = 'none'
            url_path = media['content']['url']
            genome = media['note'][0]['text']
            media_data.append([id, reference, bodySite, url_path, genome])

    #print(len(media_data))

    media_df = pd.DataFrame(media_data, columns=["patientId", "reference", "bodySite", "img_url", "note"])

    final_df = pd.merge(patients_df, media_df, on="patientId", how='inner')

    return final_df


async def gen_search_query(query_list, lst_output, media):
    dotenv.load_dotenv()
    FHIR_ADDRESS = os.getenv('FHIR_ADDRESS')
    FHIR_TOKEN = os.getenv('FHIR_TOKEN')

    # Create an instance
    client = AsyncFHIRClient(
        FHIR_ADDRESS,
        authorization=FHIR_TOKEN,
    )

    patients_dat = []
    media_dat = []
    sequence_dat = []
    df_col_names = []
    pat_param_lst = []

    if len(lst_output) == 0:
        resources_p = client.resources('Patient')
        if len(query_list) == 2: resources_p = resources_p.search(Raw(**{query_list[0]: query_list[1]}))
        if len(query_list) == 4: resources_p = resources_p.search(
            Raw(**{query_list[0]: query_list[1], query_list[2]: query_list[3]}))
        if len(query_list) == 6: resources_p = resources_p.search(
            Raw(**{query_list[0]: query_list[1], query_list[2]: query_list[3], query_list[4]: query_list[5]}))
        patients = await resources_p.limit(10).fetch()

        patient = patients[0].serialize()
        id = patient['id']
        for i in patient.keys():
            pat_param_lst.append(i)

        try:
            resources_m = client.resources('Media')
            resources_m = resources_m.search(subject__reference='Patient/' + id)
            medias = await resources_m.limit(10).fetch()
            media = medias[0].serialize()
            for i in media.keys():
                if i not in pat_param_lst: pat_param_lst.append(i)
            print(pat_param_lst)
            with open("./discovery.pkl", "wb") as disc:
                pickle.dump(pat_param_lst, disc)
            return pat_param_lst
        except:
            print(pat_param_lst)
            with open("./discovery.pkl", "wb") as disc:
                pickle.dump(pat_param_lst, disc)
            return pat_param_lst

    resources_p = client.resources('Patient')
    if len(query_list) == 2: resources_p = resources_p.search(Raw(**{query_list[0] : query_list[1]}))
    if len(query_list) == 4: resources_p = resources_p.search(Raw(**{query_list[0] : query_list[1], query_list[2] : query_list[3]}))
    if len(query_list) == 6: resources_p = resources_p.search(Raw(**{query_list[0]: query_list[1], query_list[2]: query_list[3], query_list[4] : query_list[5]}))
    patients = await resources_p.fetch_all()

    for entry in patients:
        patient = entry.serialize()
        pat_value_lst = []
        for i in lst_output:
            try:
                param = patient[i]
                pat_value_lst.append(param)
                if i not in df_col_names: df_col_names.append(i)
            except:
                if i == "link":
                    param = patient[i][0]['other']['reference']
                    pat_value_lst.append(param)
                    if i not in df_col_names: df_col_names.append(i)
        patients_dat.append(pat_value_lst)

    # print(patients_dat)
    patients_df = pd.DataFrame(patients_dat, columns=df_col_names)
    df_col_names = []

    if media == "False":
        return patients_df
    elif media == "MolSeq":
        for id in patients_dat:
            resources_s = client.resources('MolecularSequence')
            resources_s = resources_s.search(patient__reference='Patient/' + id[0])
            sequences = await resources_s.fetch_all()

            for entry in sequences:
                sequence = entry.serialize()
                sequence_value_lst = []
                for i in lst_output:
                    try:
                        param = sequence[i]
                        sequence_value_lst.append(param)
                        if i not in df_col_names: df_col_names.append(i)
                    except:
                        if i == "reference":
                            param = sequence['patient'][i]
                            sequence_value_lst.append(param)
                            if i not in df_col_names: df_col_names.append(i)
                        if i == "observedAllele":
                            param = sequence['variant'][0][i]
                            sequence_value_lst.append(param)
                            if i not in df_col_names: df_col_names.append(i)
                        continue
                sequence_dat.append(sequence_value_lst)

                # print(media_dat)
        seq_df = pd.DataFrame(sequence_dat, columns=df_col_names)

        final_df = pd.merge(patients_df, seq_df, on="id", how='inner')
        return final_df

    for id in patients_dat:
        resources_m = client.resources('Media')
        resources_m = resources_m.search(subject__reference='Patient/' + id[0])
        medias = await resources_m.fetch_all()

        for entry in medias:
            media = entry.serialize()
            media_value_lst = []
            for i in lst_output:
                try:
                    param = media[i]
                    media_value_lst.append(param)
                    if i not in df_col_names: df_col_names.append(i)
                except:
                    if i == "reference":
                        param = media['subject'][i]
                        media_value_lst.append(param)
                        if i not in df_col_names: df_col_names.append(i)
                    if i =="bodySite":
                        try:
                            param = media[i]['text']
                        except:
                            param = 'none'
                        media_value_lst.append(param)
                        if i not in df_col_names: df_col_names.append(i)
                    if i == "url_path":
                        param = media['content']['url']
                        media_value_lst.append(param)
                        if i not in df_col_names: df_col_names.append(i)
                    if i == "ground_truth":
                        param = media['note'][0]['text']
                        media_value_lst.append(param)
                        if i not in df_col_names: df_col_names.append(i)
                    continue
            media_dat.append(media_value_lst)

    # print(media_dat)
    media_df = pd.DataFrame(media_dat, columns=df_col_names)

    final_df = pd.merge(patients_df, media_df, on="id", how='inner')
    # print(final_df.describe())
    # print(final_df.to_string())

    return final_df


if __name__ == '__main__':
    query = "station_3"
    print(query)

    # loop = asyncio.get_event_loop()
    #pat_df = loop.run_until_complete(genome_query(query))

    #pat_df = loop.run_until_complete(isic_query(query))
    with open('./server_patients_s1.pkl', 'rb') as results_file:
        pat_df = pickle.load(file=results_file)

    #pat_df.to_pickle('./server_patients_s3.pkl')
    print(pat_df)

