"""
Transform, encode and select features from dataset
"""

import pandas as pd
from pandas import DataFrame
import joblib
import numpy as np
from matplotlib import pyplot as plt
import ipaddress
from sklearn.preprocessing import OneHotEncoder
from tqdm import tqdm


def load_dataset(path: str) -> DataFrame:
    """ Load csv dataset to Pandas Dataframe

    Args:
        path (str): path to csv file

    Returns:
        DataFrame: DataFrame of dataset
    """    
    return pd.read_csv(path)


def label_data(data: DataFrame, column: str, label_mapping: dict) -> DataFrame:
    """_summary_

    Args:
        data (DataFrame): _description_
        column (str): _description_
        label_mapping (dict): _description_

    Returns:
        DataFrame: _description_
    """    

    progress_bar = tqdm(total=len(data), desc='Label Encoding')

    for i, value in enumerate(data[column]):
        data.at[i, column] = label_mapping[value]
        progress_bar.update(1)

    progress_bar.close()

    data[column] = data[column].astype('int64')

    return data