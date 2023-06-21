"""
This module houses the Streamlit frontend for the app.

It allows the user to upload sample credit card data as .csv file and choose which prediction model to use
from a range of pretrained models.

The result is presented as percentage probability to default on credit card payment
"""

import os
import time
import asyncio
import threading
import pandas as pd
import streamlit as st
import pyshark
import requests
from src.utils.frontend_log_config import frontend as logger
from src.data.packet_streamer import pcap_stream
from src.models.predict_model import reversed_label

# specify temporary files folder
temp_folder = os.path.join(os.path.dirname(__file__), "temp")
os.makedirs(temp_folder, exist_ok=True)

def run_pyshark():
    
    capture = pyshark.FileCapture('../data/external/dos-synflooding-5-dec.pcap')
    
    # Rest of your Pyshark code goes here

    for packet in pcap_stream(capture):
        # st.dataframe(display_data)
        start_time = time.perf_counter()

        response = requests.post("http://127.0.0.1:8000/predict", data={"data":packet}).json()

        prediction = response["result"]
        pred_time = response["time"]

        # Increment total prediction time
        # TOTAL_PRED_TIME+=pred_time

        # Increment total counter
        # TOTAL+=1

        if prediction==0.0:
            st.info('\n', {'packet_type': reversed_label[int(0.0)]}, '\n')
            # Increment normal count
            
        
        else:
            st.info('\n', {'packet_type': reversed_label[int(prediction)],
                    'packet': packet.to_dict(orient='records')[0]}, '\n')
            # Increment attack count
                            
    
    capture.close()
    loop.close()

def run():
    """
    Streamlit configuration for Credit Card Default Prediction web user interface

    - Allows user to upload sample credit card data
    - Allows user to select prediction model to be used
    - Sends request to backend API for prediction and then displays result
    """
    logger.info("Session started")
    st.set_page_config(page_title="IDS for IoT Systems",
                       page_icon="🔐")
    st.image("https://www.n-able.com/wp-content/uploads/2021/03/blog-ids_IPS_main.jpeg")
    st.title("Cloud Based IDS for IoT Systems")
    st.subheader("Built with XGBoost ML Model\n")

    st.sidebar.text("Steps:\n"
                    "1. Upload packet data\n"
                    "2. Initialize IDS\n"
                    "3. Get packet flags")
    with st.spinner("Uploading file..."):
        file = st.file_uploader("Upload network packet data (PCAP)", type=['pcap', 'pcapng'])


    if file is not None:
        logger.info("network packet data uploaded")

        filename = os.path.join(temp_folder, file.name)
        with open(filename, "wb") as f:
            f.write(file.getbuffer())
        logger.info(f"network packet data saved to '{file.name}'")
        
        with st.spinner("Processing file..."):
            state = requests.post("http://127.0.0.1:8000/process", json={"filename":filename}).json()
            st.info(state['response'])
        
        if state['response']=='Processing complete!':
            if st.button("Activate IDS"):
                with st.container():
                    try:
                        logger.info("Attempting API call")
                        # Initialize counters
                        TOTAL = 0
                        NORMAL = 0
                        ATTACK = 0
                        TOTAL_PRED_TIME = 0
                        display_data = pd.DataFrame()
                        
                        pyshark_thread = threading.Thread(target=asyncio.run, args=(run_pyshark(),))
                        pyshark_thread.start()
                        pyshark_thread.join()
                        # for packet in pcap_stream(capture):
                        #     st.dataframe(display_data)
                        #     start_time = time.perf_counter()

                        #     response = requests.post("http://127.0.0.1:8000/predict", data={"data":packet}).json()

                        #     prediction = response["result"]
                        #     pred_time = response["time"]

                        #     # Increment total prediction time
                        #     TOTAL_PRED_TIME+=pred_time

                        #     # Increment total counter
                        #     TOTAL+=1

                        #     if prediction==0.0:
                        #         print('\n', {'packet_type': reversed_label[int(0.0)]}, '\n')
                        #         # Increment normal count
                        #         NORMAL+=1
                            
                        #     else:
                        #         print('\n', {'packet_type': reversed_label[int(prediction)],
                        #                 'packet': packet.to_dict(orient='records')[0]}, '\n')
                        #         # Increment attack count
                        #         ATTACK+=1

                        #     elapsed_time = time.perf_counter() - start_time



                        st.success(f"All packets scanned successfully")
                        st.success(
                            f"\nTotal Packets: {TOTAL}\n",
                            f"Normal Packets: {NORMAL}\n",
                            f"Attack Packets: {ATTACK}"
                        )
                        st.success(f"Avg. prediction time: {(TOTAL_PRED_TIME/TOTAL):.10f}s\n")
                        st.success(f"Overall run time: {elapsed_time:.3f}s")

                    except Exception as e:
                        st.error("Error: Please check the file or your network connection: \n" + str(e))
                        logger.info(f"An error occurred whilst attempting to call API:\n{e}")


if __name__ == "__main__":
        run()