"""
Train ML model 
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

# Load training data
X_TRAIN_PATH = './data/processed/X_train_scaled.csv'
Y_TRAIN_PATH = './data/processed/y_train.csv'
X_TEST_PATH = './data/processed/X_test_scaled.csv'
Y_TEST_PATH = './data/processed/y_test.csv'
X_train_scaled = np.genfromtxt(X_TRAIN_PATH, delimiter=',')
y_train = np.genfromtxt(Y_TRAIN_PATH, delimiter=',', skip_header=1)
X_test_scaled = np.genfromtxt(X_TEST_PATH, delimiter=',')
y_test = np.genfromtxt(Y_TEST_PATH, delimiter=',', skip_header=1)

# Define path to save model
MODELS_DIR = './models/'

# XGB model parameters
xgb_params = {
    'objective': 'multi:softmax',
    'num_class': 11,  
    'max_depth': 5,
    'learning_rate': 0.1,
    'n_estimators': 100,
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
joblib.dump(xgb_model, MODELS_DIR+'xgb_model.joblib')


## ------------- Evaluate the model ----------------- ##

# XGB Predictions
st = time.process_time()
dtest = xgb.DMatrix(X_test_scaled)
xgb_preds = xgb_model.predict(dtest)
xgb_inf_time = time.process_time() - st


# Save training and evaluation metrics
def get_metrics(y_true: np.ndarray,
                y_pred: np.ndarray,
                train_time: float,
                inference_time: float, 
                path: float) -> dict:
    """Summarize key metrics into a JSON file

    Args:
        y_true (np.ndarray): NDArray of true labels
        y_pred (np.ndarray): NDArray of predicted labels
        train_time (float): Time elapsed in training the model
        inference_time (float): Total time taken to make predictions on test data
        path (float): Path to save JSON file

    Returns:
        dict: _description_
    """    

    # Initialize metrics dictionary
    metrics = {}

    # Update Train and Inference time
    metrics.update({"train_time": train_time})
    metrics.update({"inf_time/d_point": inference_time/len(y_pred)})


    # Generate F1 Score report
    report = classification_report(y_true, y_pred, output_dict=True)

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
        fp=open(path+'metrics.json', 'w'),
        indent = 4,
        sort_keys = True
    )

    return metrics


model_metrics = get_metrics(y_true=y_test,
                            y_pred=xgb_preds,
                            train_time=xgb_train_time,
                            inference_time=xgb_inf_time,
                            path=MODELS_DIR)

print(model_metrics)

