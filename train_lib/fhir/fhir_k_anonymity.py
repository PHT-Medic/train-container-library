from typing import List
import pandas as pd
from pandas.api.types import is_datetime64_any_dtype as is_datetime
from pandas.api.types import is_numeric_dtype, is_string_dtype, is_categorical_dtype
from icecream import ic


def is_k_anonymized(df: pd.DataFrame, k: int = 3, id_cols: List[str] = None):
    for index, row in df.iterrows():
        if id_cols:
            query = ' & '.join([f'{col} == "{row[col]}"' for col in id_cols])
        else:
            query = ' & '.join([f'{col} == "{row[col]}"' for col in df.columns])
        rows = df.query(query)
        if rows.shape[0] < k:
            return False
    return True


def anonymize(df: pd.DataFrame, k: int = 3, id_cols: List[str] = None):
    anon_df = df.copy()

    # If id cols are given anonymize those otherwise use all columns
    for col in id_cols if id_cols else df.columns:
        if is_datetime(df[col]):
            anon_df[col] = generalize_datetime_column(df[col])

        elif is_numeric_dtype(df[col]):
            anon_df[col] = generalize_numeric_column(df[col])

        elif is_string_dtype(df[col]) or is_categorical_dtype(df[col]):
            # TODO categorical/string variable handling
            anon_df[col] = df[col]

        else:
            anon_df[col] = anon_df[col]

    if is_k_anonymized(anon_df, k=k):
        return anon_df

    else:
        print("More generalization required")


def generalize_numeric_column(num_col: pd.Series):
    return num_col


def generalize_datetime_column(date_col: pd.Series, level: int = 2):
    col = pd.to_datetime(date_col)

    if level == 2:
        generalized_col = col.apply(lambda x: x.strftime('m-%Y'))
        return generalized_col

    elif level == 3:
        generalized_col = col.apply(lambda x: x.strftime('%Y'))
        return generalized_col


if __name__ == '__main__':
    df = pd.read_csv("query_results.csv")

    df_no_id = df.copy()[["birthDate", "gender"]]
    df_no_id["birthDate"] = pd.to_datetime(df_no_id["birthDate"], infer_datetime_format=True)
    ic(df_no_id["birthDate"].dtype)
    ic("not generalized k-anon: ", is_k_anonymized(df_no_id))
    for col in df_no_id.columns:
        ic(col, type(col))
    anon_df_dt = anonymize(df, id_cols=["birthDate", "gender"])
    ic(anon_df_dt["birthDate"])
    ic("generalized k-anon: ", is_k_anonymized(anon_df_dt))