import joblib
from src.features.build_features import preprocess, label_mapping

MODEL_DIR = './models/xgb_model.joblib'
model = joblib.load(MODEL_DIR)

def predct(data):

    prediction = None
    if prediction==0.0:
        return {'packet_type': label_mapping[int(0.0)]}
    
    else:
        return {'packet_type': label_mapping[int(prediction)],
                'packet': i}