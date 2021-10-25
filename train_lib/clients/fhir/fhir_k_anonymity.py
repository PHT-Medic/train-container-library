from typing import List
import pandas as pd
from pandas.api.types import is_datetime64_any_dtype as is_datetime
from pandas.api.types import is_numeric_dtype, is_string_dtype, is_categorical_dtype


def is_k_anonymized(df: pd.DataFrame, k: int = 3, id_cols: List[str] = None):
    """
    Checks if a dataframe satisfies k-anonymity for the given k. If id_cols is given only these columns are checked
    :param df: dataframe to check for k-anonymity
    :param k: the number samples that need to have the same values
    :param id_cols: optional subset of columns in the dataframe that are exclusively checked for k-anonymity
    :return: boolean indicating wether the dataframe satisfies k-anonymity
    """

    for index, row in df.iterrows():
        if id_cols:
            query = ' & '.join([f'{col} == "{row[col]}"' for col in id_cols])
        else:
            query = ' & '.join([f'{col} == "{row[col]}"' for col in df.columns])
        rows = df.query(query)
        if rows.shape[0] < k:
            return False
    return True


def anonymize(df: pd.DataFrame, k: int = 3, id_cols: List[str] = None) -> pd.DataFrame:
    """
    Attempts to generalize the given dataframe to make it k-anonymized

    :param df: dataframe to check
    :param k:
    :param id_cols: optional parameter specifying a subset of columns in the dataframe to generalize
    :return:
    """
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
        return pd.to_datetime(generalized_col)

    elif level == 3:
        generalized_col = col.apply(lambda x: x.strftime('%Y'))
        return pd.to_datetime(generalized_col)
