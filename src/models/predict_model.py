import joblib
import pandas as pd
import pyshark
from xgboost import DMatrix
from src.features.build_features import preprocess, label_mapping
from src.data.packet_streamer import pcap_stream

MODEL_DIR = './models/xgb_model.joblib'
model = joblib.load(MODEL_DIR)

reversed_label = {value: key for key, value in label_mapping.items()}



def get_inference(data):
    print('running')

    # Initialize counters
    TOTAL = 0
    NORMAL = 0
    ATTACK = 0

    for packet in pcap_stream(data):
        
        data_point = preprocess(packet, train=False)
        data_point = DMatrix(data_point)
        prediction = model.predict(data_point)
        # Increment total count
        TOTAL+=1

        if prediction==0.0:
            print('\n', {'packet_type': reversed_label[int(0.0)]}, '\n')
            # Increment normal count
            NORMAL+=1
        
        else:
            print('\n', {'packet_type': reversed_label[int(prediction)],
                    'packet': packet.to_dict(orient='records')[0]}, '\n')
            # Increment attack count
            ATTACK+=1

    print(
        f"\nTotal Packets: {TOTAL}\n",
        f"Normal Packets: {NORMAL}\n",
        f"Attack Packets: {ATTACK}"
    )

print(get_inference('./data/external/dos-synflooding-5-dec.pcap'))
