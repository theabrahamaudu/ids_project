"""
Train and evaluate ML model 
"""
# General
import time
import json
import joblib
import numpy as np
# ML Model
import xgboost as xgb
# Evaluation
from sklearn.metrics import classification_report


def train_model(MODELS_DIR: str, X_TRAIN_PATH: str, Y_TRAIN_PATH: str) -> float:
    """Train XGBoost Model 

    Args:
        MODELS_DIR (str): Path to save trained model
        X_TRAIN_PATH (str): Path to load train features
        Y_TRAIN_PATH (str): Path to load train targets

    Returns:
        float: Model training time
    """    

    # Load train data from memory
    X_train_scaled = np.genfromtxt(X_TRAIN_PATH, delimiter=',')
    y_train = np.genfromtxt(Y_TRAIN_PATH, delimiter=',', skip_header=1)

    # XGB model parameters
    xgb_params = {
        'objective': 'multi:softmax',
        'num_class': 11,  
        'max_depth': 5,
        'learning_rate': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'eval_metric': 'merror'
    }

    # Convert the training data to XGBoost's DMatrix format
    dtrain = xgb.DMatrix(X_train_scaled, label=y_train)

    # Train the XGBoost model
    st = time.process_time()
    xgb_model = xgb.train(xgb_params, dtrain)
    xgb_train_time = time.process_time() - st

    # Save model
    xgb_model.save_model(MODELS_DIR+'xgb_model.bin')

    return xgb_train_time


## ------------- Evaluate the model ----------------- ##

def evaluate_model(MODELS_DIR: str,
                   X_TEST_PATH: str,
                   Y_TEST_PATH: str,
                   train_time: float,
                ) -> dict:
    """Evaluate trained model.

    Evaluate model with test data, dump model train time,
    average inference time, label-based and overall F1-Scores 
    as `JSON` to memory and return same metrics as `dict`.

    Args:
        MODELS_DIR (str): Path to load trained model
        X_TEST_PATH (str): Path to load test features
        Y_TEST_PATH (str): Path to load test features
        train_time (float): return value from `train_model` function

    Returns:
        dict: Evaluation metrics
    """
    
    X_test_scaled = np.genfromtxt(X_TEST_PATH, delimiter=',')
    y_test = np.genfromtxt(Y_TEST_PATH, delimiter=',', skip_header=1)

    # Load model
    loaded_model = xgb.Booster()
    loaded_model.load_model(MODELS_DIR+'xgb_model.bin')


    # XGB Predictions
    st = time.process_time()
    dtest = xgb.DMatrix(X_test_scaled)
    xgb_preds = loaded_model.predict(dtest)
    xgb_inf_time = time.process_time() - st

    # Initialize metrics dictionary
    metrics = {}

    # Update Train and Inference time
    metrics.update({"train_time": train_time})
    metrics.update({"inf_time/d_point": xgb_inf_time/len(xgb_preds)})


    # Generate F1 Score report
    report = classification_report(y_test, xgb_preds, output_dict=True)

    # Update F1 Scores
    for class_label, metric in report.items():
        try:
            f1_score_float = metric['f1-score']
            if '.' in class_label:
                metrics.update({f"class {class_label}": round(f1_score_float, 3)})
            elif 'avg' in class_label:
                metrics.update({f"F1 {class_label}": round(f1_score_float, 3)})
        except:
            pass
    
    # Save metrics to json file
    json.dump(
        obj=metrics,
        fp=open(MODELS_DIR+'metrics.json', 'w'),
        indent = 4,
        sort_keys = True
    )

    return metrics

## ----------- Run Train and Eval Pipeline ---------- ##
# if __name__ == "__main__":
#     # Define path to save model
#     MODELS_DIR = './models/'
#     # Training data paths
#     X_TRAIN_PATH = './data/processed/X_train_scaled.csv'
#     Y_TRAIN_PATH = './data/processed/y_train.csv'

#     # Test data paths
#     X_TEST_PATH = './data/processed/X_test_scaled.csv'
#     Y_TEST_PATH = './data/processed/y_test.csv'

#     train_time = train_model(MODELS_DIR, X_TRAIN_PATH, Y_TRAIN_PATH)

#     eval_metrics = evaluate_model(MODELS_DIR,
#                                   X_TEST_PATH,
#                                   Y_TEST_PATH,
#                                   train_time
#                                 )