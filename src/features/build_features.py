"""
Transform, encode and select features from dataset
"""

import warnings
import pandas as pd
from pandas import DataFrame
import joblib
import numpy as np
from numpy import ndarray
from matplotlib import pyplot as plt
import ipaddress
from sklearn.preprocessing import OneHotEncoder
from tqdm import tqdm

# Model and Optimization 
from sklearn.preprocessing import StandardScaler, Normalizer, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import RFE
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import f1_score, classification_report

# Ignore  "SettingWithCopyWarning" 
from pandas.errors import SettingWithCopyWarning
warnings.simplefilter(action="ignore", category=SettingWithCopyWarning)


def load_data(path: str, Numpy: bool=True):
    """ Load csv data to Numpy Array or Pandas Dataframe.
    
    Primarily designed for loading preprocessed data from memory.

    Args:
        path (str): path to csv file

    Returns:
        NDArray or DataFrame: NDArray or DataFrame of data
    """    
    if Numpy==True:
        return np.genfromtxt(path, delimiter=',')
    else:
        return pd.read_csv(path)


def get_features(data: DataFrame, optimal_features: list, train: bool=True) -> DataFrame:
    """Filter for optimal features (from feature selection experiments) from full dataset.

    Args:
        data (DataFrame): DataFrame with all features
        optimal_features (list, optional): List of optimal features. 
                                           Defaults to predefined list.
        train (bool, optional): _description_. Defaults to True.

    Returns:
        DataFrame: DataFrame with only optimal features
    """ 
    if train==True:
        # Add 'label' to columns to be used
        train_features = optimal_features.copy()
        train_features.append('label')
        # Extract columns to be sued from full dataset
        data_optimal_features = data[train_features]

        return data_optimal_features
    else:
        # Extract columns to be sued from full dataset   
        data_optimal_features = data[optimal_features]

        return data_optimal_features


def label_data(data: DataFrame, column: str, label_mapping: dict) -> DataFrame:
    """
    Labels specified column in dataset based on mapping provided

    Args:
        data (DataFrame): _description_
        column (str): _description_
        label_mapping (dict): _description_

    Returns:
        DataFrame: Dataset with `int` encoded label column
    """    

    progress_bar = tqdm(total=len(data), desc='Label Encoding', unit=" rows")

    for i, value in enumerate(data[column]):
        data.at[i, column] = label_mapping[value]
        progress_bar.update(1)

    progress_bar.close()

    data[column] = data[column].astype('int64')

    return data


def undersample_data(data: DataFrame, label_column: str) -> DataFrame:
    """Undersample data points with label count greater than the mean label count of the dataset.

    Undersampling Strategy:
        `(label count / total label count) * mean label count`

    This ensures that the overpopulated labels are trimmed proportionally, as opposed to 
    trimming all oversampled points to a fixed number, thus retaining the underlying
    difference in frequency, but still preventing excessive skew in distribution.

    Args:
        data (DataFrame): DataFrame to be undersampled
        label_column (str): Column holding the labels

    Returns:
        DataFrame: Undersampled DataFrame
    """    
    value_counts = data[label_column].value_counts()
    mean_count = value_counts.mean()

    undersampled_data = pd.DataFrame(columns=data.columns)

    for value, count in value_counts.items():
        if count > mean_count:
            undersampled_count = int((count / value_counts.sum()) * mean_count)
            subset = data[data[label_column] == value].sample(n=undersampled_count, random_state=42)
            undersampled_data = pd.concat([undersampled_data, subset], ignore_index=True)
        else:
            subset = data[data[label_column] == value]
            undersampled_data = pd.concat([undersampled_data, subset], ignore_index=True)

    # Randomize the undersampled data
    randomized_data = undersampled_data.sample(frac=1, random_state=42)

    return randomized_data


def convert_to_float(data: DataFrame) -> DataFrame:
    """Parse Dataframe columns and convert all values to float

    Args:
        data (DataFrame): DataFrame to be parsed

    Returns:
        DataFrame: DataFrame with all columns as floats
    """
    if 'tcp_flags_str' in data.columns or 'tcp_flags_fin' in data.columns:
        # Drop the 'tcp_flags_str' and 'tcp_flags_fin' column
        data = data.drop(['tcp_flags_str', 'tcp_flags_fin'], axis=1)  
    
    # Setup progress bar
    progress_bar = tqdm(total=(len(data.columns) * len(data)),
                        desc='Converting to float64',
                        unit = ' data points')
    
    for col in data.columns:

        # Initialize list of converted values for each column
        converted_values = []

        for value in data[col]:

            if pd.isna(value):
                converted_values.append(-3)  # Assign -3 for NaN values
            elif isinstance(value, (int, float)):
                converted_values.append(float(value))  # Convert numbers to float
            elif isinstance(value, str):
                try:
                    if value.startswith('0x'):
                        converted_values.append(int(value, 16))  # Convert hexadecimal string to int
                    elif '.' in value:
                        parts = value.split('.')
                        if len(parts) == 4:
                            ip = ipaddress.ip_address(value)
                            converted_values.append(int(ip))  # Convert IP address to int
                        else:
                            converted_values.append(float(value))  # Convert string representation of float to float
                    else:
                        converted_values.append(-4)  # Assign -4 for regular text values
                except ValueError:
                    converted_values.append(-4)  # Assign -4 for text that cannot be converted
                except ipaddress.AddressValueError:
                    converted_values.append(-4)  # Assign -4 for invalid IP addresses
            else:
                converted_values.append(-4)  # Assign -4 for other non-convertible values
            
            # update progress bar
            progress_bar.update(1)

        data[col] = converted_values
        data[col] = data[col].astype('float64')  # Typecast the column to float64

    # close progress bar
    progress_bar.close()

    return data


def split(data: DataFrame, target_col: str):
    """Split data into train and test sets

    Uses the `train_test_split` method from `sklearn.model_selection`

    Args:
        data (DataFrame): DataFrame to be split
        target_col (str): Prediction target column

    Returns:
        DataFrame(s): Four dataframes in this order:
            X_train, X_test, y_train, y_test
    """    
    X = data.drop(target_col, axis=1) # Inputs
    y = data[target_col] # Target

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, 
                                                        random_state=42, 
                                                        stratify=y,
                                                        shuffle=True)
    
    return X_train, X_test, y_train, y_test


def scale_data(data: DataFrame=None, 
               X_train: DataFrame=None, 
               X_test: DataFrame=None, 
               train: bool=True):
    """Scale input data using `StandardScaler` and return Numpy array of the data.

    If train is set to true, fits scaler to X_train, saves scaler to memory and
    transforms X_train and X_test to scaled Numpy arrays.

    If train is set to false, loads scaler from memory, transforms data and
    returns scaled data Numpy array.

    Args:
        data (DataFrame, optional): Data for inference generation. Defaults to None.
        X_train (DataFrame, optional): Features set for training. Defaults to None.
        X_test (DataFrame, optional): Features set for testing. Defaults to None.
        train (bool, optional): if True, does not use `data` arg. Defaults to True.

    Returns:
        np.array: X_train_scaled, X_test_scaled if train==True
                       data_scaled if train==False
    """    
    
    if train ==True:
        scaler = StandardScaler().fit(X_train)
        joblib.dump(scaler, './src/features/scaler.pkl')
        scaler = joblib.load('./src/features/scaler.pkl')

        X_train_scaled = scaler.transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        return X_train_scaled, X_test_scaled
    
    else:
        scaler = joblib.load('./src/features/scaler.pkl')
        data_scaled = scaler.transform(data)

        return data_scaled

label_mapping: dict={
                    'normal':0, 'dos_synflooding':1, 'mirai_ackflooding':2, 'host_discovery':3,
                    'telnet_bruteforce':4, 'mirai_httpflooding':5, 'mirai_udpflooding':6,
                    'mitm_arpspoofing':7, 'scanning_host':8, 'scanning_port':9, 'scanning_os':10
                    }

def preprocess(data: DataFrame,
               train: bool=True,
               save: bool=True,
               path: str = './data/processed/',
               label_col: str = 'label',
               optimal_features: list=[
                'timestamp', 'ip_len', 'ip_id', 'ip_flags', 'ip_ttl', 'ip_proto',
                'ip_checksum', 'ip_dst', 'ip_dst_host','tcp_srcport', 'tcp_dstport',
                'tcp_port', 'tcp_stream', 'tcp_completeness', 'tcp_seq_raw', 'tcp_ack',
                'tcp_ack_raw', 'tcp_flags_reset', 'tcp_flags_syn', 'tcp_window_size_value',
                'tcp_window_size', 'tcp_window_size_scalefactor', 'tcp_', 'udp_srcport',
                'udp_dstport', 'udp_port', 'udp_length', 'udp_time_delta', 'eth_dst_oui',
                'eth_addr_oui', 'eth_dst_lg', 'eth_lg', 'eth_ig', 'eth_src_oui', 'eth_type',
                'icmp_type', 'icmp_code', 'icmp_checksum', 'icmp_checksum_status', 'arp_opcode'
                ],
                label_mapping: dict={
                    'normal':0, 'dos_synflooding':1, 'mirai_ackflooding':2, 'host_discovery':3,
                    'telnet_bruteforce':4, 'mirai_httpflooding':5, 'mirai_udpflooding':6,
                    'mitm_arpspoofing':7, 'scanning_host':8, 'scanning_port':9, 'scanning_os':10
                    }):
    """Pipeline to apply all preprocessing steps defined in `build_features` module to dataset.

    Extract optimal features from raw dataset, encode `str` labels to `int`, undersample imbalanced
    labels, convert all features to `float`, split data into train and test set, and scale train
    and test set.


    Args:
        data (DataFrame): Raw data to be preprocessed
        train (bool, optional): if False, skips steps required only for training. Defaults to True.
        save (bool, optional): if False, returns preprocessed data without dumping to memory. Defaults to True.
        path (str, optional): Path to save preprocessed data. Defaults to './data/processed/'.
        label_col (str, optional): Name of column with data label. Defaults to 'label'.
        optimal_features (list, optional): List of features to be extracted from raw data. Defaults to predefined list.
        label_mapping (_type_, optional): str to int dictionary for label encoding. Defaults to predefined dictionary.

    Returns:
        X_train_scaled (NDArray), X_test_scaled (NDArray), y_train (DataFrame), y_test (DataFrame): if train==True
        data (DataFrame): if train==False
    """    

    if train==True:
        data = get_features(data, optimal_features, train=True)
        data = label_data(data, label_col, label_mapping)
        data = undersample_data(data, label_col)
        data = convert_to_float(data)
        X_train, X_test, y_train, y_test = split(data, label_col)
        X_train_scaled, X_test_scaled = scale_data(X_train=X_train,
                                                   X_test=X_test,
                                                   train=True)

        y_train = y_train.astype(int)
        y_test = y_test.astype(int)
        if save==True:
            np.savetxt(str(path+'X_train_scaled.csv'), X_train_scaled, delimiter=',')
            np.savetxt(str(path+'X_test_scaled.csv'), X_test_scaled, delimiter=',')
            y_train.to_csv(str(path+'y_train.csv'), index=False, header=True, mode='w')
            y_test.to_csv(str(path+'y_test.csv'), index=False, header=True, mode='w')


        return X_train_scaled, X_test_scaled, y_train, y_test
    
    else:
        data = get_features(data, optimal_features, train=False)
        data = convert_to_float(data)
        data = scale_data(data=data, train=False)

        return data
    
def inference_preprocess(data: DataFrame) -> ndarray:
    """Preprocessing pipeline for inference data.

    Extract optimal features, convert data to float and apply scaler 
    from memory. 

    Args:
        data (DataFrame): Data to be preprocessed

    Returns:
        ndarray: Preprocessed data
    """    
    optimal_features=[
        'timestamp', 'ip_len', 'ip_id', 'ip_flags', 'ip_ttl', 'ip_proto',
        'ip_checksum', 'ip_dst', 'ip_dst_host','tcp_srcport', 'tcp_dstport',
        'tcp_port', 'tcp_stream', 'tcp_completeness', 'tcp_seq_raw', 'tcp_ack',
        'tcp_ack_raw', 'tcp_flags_reset', 'tcp_flags_syn', 'tcp_window_size_value',
        'tcp_window_size', 'tcp_window_size_scalefactor', 'tcp_', 'udp_srcport',
        'udp_dstport', 'udp_port', 'udp_length', 'udp_time_delta', 'eth_dst_oui',
        'eth_addr_oui', 'eth_dst_lg', 'eth_lg', 'eth_ig', 'eth_src_oui', 'eth_type',
        'icmp_type', 'icmp_code', 'icmp_checksum', 'icmp_checksum_status', 'arp_opcode'
        ]
    scaler = joblib.load('./src/features/scaler.pkl')

    data_optimal_features = data[optimal_features]
    data_floats = convert_to_float(data_optimal_features)
    data_scaled = scaler.transform(data_floats)

    return data_scaled



    
## -------------- Uncomment to Preprocess Labelled Dataset -------------------##
# if __name__=='__main__':

#     raw_data = pd.read_csv('./data/labelled/all_data_labelled.csv')

#     X_train_scaled, X_test_scaled, y_train, y_test = preprocess(data=raw_data,
#                                                                 train=True,
#                                                                 save=True)
    

#     print('train features shape:')
#     print(X_train_scaled.shape)

#     print('\ntest features shape:')
#     print(X_test_scaled.shape)

#     print("\ntrain targets shape")
#     print(y_train.shape)

#     print("\ntest targets shape")
#     print(y_test.shape)   

