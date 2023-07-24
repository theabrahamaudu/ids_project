"""This Module runs the entire pipeline from raw network packets
to model training and evaluation
"""

import pandas as pd
from src.data.load_n_filter import scan_directory, load_and_filter_files
from src.features.build_features import preprocess
from src.models.train_model import train_model, evaluate_model
from src.utils.pipeline_log_config import pipeline as logger

logger.info("Initializing full pipeline")
## ---------- Load, Filter and Label Data ------------ ##
logger.info("Loading, filtering and labeling data")
try:
    # Specify the directory to scan
    directory_path = "./data/external"

    # Labelled data directory
    destination_path = './data/labelled'

    # Call the function to scan the directory and get the list of .pcap files
    pcap_files_list = scan_directory(directory_path, ".pcap")

    # Remove noted bad files
    bad_files = ['dos-synflooding-6-dec.pcap', 'mirai-hostbruteforce-3-dec.pcap']

    for file in bad_files:
        if file in pcap_files_list: 
            pcap_files_list.remove(file)

    # Initiate load and filter step
    load_and_filter_files(directory_path=directory_path,
                        pcap_files_list=pcap_files_list,
                        destination_path=destination_path,
                        merge=True,
                        pick_up=True
                        )
    logger.info("Loading, filtering and labeling complete")
except Exception as e:
    logger.warning(f"Error loading, filtering and labeling data:\n{e}")

## ----------- Preprocess and Split Data ------------ ##
logger.info('Preprocessing and splitting data')
try:
    labelled_data = pd.read_csv('./data/labelled/all_data_labelled.csv')

    X_train_scaled, X_test_scaled, y_train, y_test = preprocess(data=labelled_data,
                                                                train=True,
                                                                save=True)
    logger.info('Preprocessing and splitting complete')
except Exception as e:
    logger.warning(f'Error preprocessing and splitting data:\n{e}')

## ------------------- Train Model ------------------- ##
logger.info('Training model')
try:
    # Define path to save model
    MODELS_DIR = './models/'
    # Training data paths
    X_TRAIN_PATH = './data/processed/X_train_scaled.csv'
    Y_TRAIN_PATH = './data/processed/y_train.csv'

    train_time = train_model(MODELS_DIR, X_TRAIN_PATH, Y_TRAIN_PATH)
    logger.info('Model training complete')
except Exception as e:
    logger.warning(f"Error training model:\n{e}")


## ------------------ Evaluate Model ----------------- ##
logger.info("Evaluating model")
try:
    # Define path to load model
    MODELS_DIR = './models/'
    # Test data paths
    X_TEST_PATH = './data/processed/X_test_scaled.csv'
    Y_TEST_PATH = './data/processed/y_test.csv'

    eval_metrics = evaluate_model(MODELS_DIR,
                                X_TEST_PATH,
                                Y_TEST_PATH,
                                train_time
                                )
    logger.info('Model evaluation complete')
except Exception as e:
    logger.warning(f"Error evaluating model:\n{e}")