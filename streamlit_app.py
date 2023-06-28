"""
This module houses the Streamlit frontend for the app.

It allows the user to upload sample credit card data as .csv file and choose which prediction model to use
from a range of pretrained models.

The result is presented as percentage probability to default on credit card payment
"""

import os
import time
import pandas as pd
import numpy as np
import streamlit as st
from io import StringIO, BytesIO
import zipfile
from collections import OrderedDict


import requests


# data label mapping
label_mapping: dict={
                    'normal':0, 'dos_synflooding':1, 'mirai_ackflooding':2, 'host_discovery':3,
                    'telnet_bruteforce':4, 'mirai_httpflooding':5, 'mirai_udpflooding':6,
                    'mitm_arpspoofing':7, 'scanning_host':8, 'scanning_port':9, 'scanning_os':10
                    }
reversed_label = {value: key for key, value in label_mapping.items()}

# specify temporary files folder
temp_folder = os.path.join(os.path.dirname(__file__), "temp")
os.makedirs(temp_folder, exist_ok=True)

server: str = 'https://54.227.227.65' # Deployment
# server: str = 'http://127.0.0.1:8000' # Local



def convert_df(df):
    # IMPORTANT: Cache the conversion to prevent computation on every rerun
    return df.to_csv().encode('utf-8')

def run():
    """
    Streamlit configuration for Credit Card Default Prediction web user interface

    - Allows user to upload sample credit card data
    - Allows user to select prediction model to be used
    - Sends request to backend API for prediction and then displays result
    """
    # logger.info("Session started")
    st.set_page_config(page_title="IDS for IoT Systems",
                        page_icon="🔐")
    st.image("https://www.n-able.com/wp-content/uploads/2021/03/blog-ids_IPS_main.jpeg")
    st.title("Cloud Based IDS for IoT Systems")
    st.subheader("Built with XGBoost ML Model\n")

    st.sidebar.text("Steps:\n"
                    "1. Upload packet data\n"
                    "2. Initialize IDS\n"
                    "3. Get packet flags")
    with st.spinner("Adding file to queue"):
        file = st.file_uploader("Choose network packet data (PCAP)", type=['pcap', 'pcapng'])


    if file is not None:
        # Create a session state object
        st.session_state['filename'] = file.name
        if st.button("Upload"):
            with st.spinner("Uploading file..."):
                up_status = requests.post(server+"/upload", files={"file":file}, verify=False)
                if up_status.status_code == 200:
                    up_status = up_status.json()
                    st.session_state['filename'] = up_status['filename']
                    st.success(f"File uploaded successfully!")
                else:
                    st.error("File upload failed.")

        
        if st.button("Process data"):
            with st.spinner("Processing file..."):
                state = requests.post(server+"/process", json={"filename":st.session_state['filename']}, verify=False).json()
                if "complete" in str(state['response']):
                    st.info(state['response'])
                else:
                    st.warning(state['response'])
        if st.button("Activate IDS"):
            try:
                st.info("Calling API engine")
                with st.spinner("Retrieving processed file..."):
                    # Make a POST request to the endpoint and provide the file path
                    filename = {'filename': st.session_state['filename']}
                    processed_file = requests.post(server+"/retrieve", json=filename, verify=False)

                    # Check if the request was successful (status code 200)
                    if processed_file.status_code == 200:
                        try:
                            # Throw error if file has dictionary
                            response_dict = processed_file.json()
                            st.warning(response_dict['response'])
                        except: 
                            # Access the CSV file content from the response
                            csv_content = processed_file.content
                            st.info("Processed packets retrived")

                                
                
                # Initialize counters
                TOTAL = 0
                NORMAL = 0
                ATTACK = 0
                TOTAL_PRED_TIME = 0
                display_data = pd.DataFrame()
                
                zip_file = zipfile.ZipFile(BytesIO(csv_content))

                # Extract the CSV files from the zip archive
                csv_files = [filename for filename in zip_file.namelist() if filename.endswith('.csv')]

                if len(csv_files) >= 2:
                    # Read the first CSV file into a DataFrame
                    csv_data1 = zip_file.read(csv_files[1])
                    packets_df = pd.read_csv(BytesIO(csv_data1))

                    # Read the second CSV file into a NumPy array
                    csv_data2 = zip_file.read(csv_files[0])
                    packets_arr = np.genfromtxt(BytesIO(csv_data2), delimiter=',')

                st.info('Initializing streaming process')

                session = requests.session()
                progress_bar = st.progress(0.0, text="Analysing packets...")
                start_time = time.perf_counter()
                with st.empty():
                    for packet_row, row in zip(range(len(packets_arr)), range(len(packets_df))):
                        
                        packet = packets_arr[packet_row]
                        packet = OrderedDict(enumerate(packet))

                        
                        response = session.post(server+"/predict", json={"data":packet}, verify=False).json()
                        # time.sleep(0.3)
                        prediction = response["result"]
                        pred_time = response["time"]

                        # Increment total prediction time
                        TOTAL_PRED_TIME+=pred_time

                        # Increment total counter
                        TOTAL+=1

                        progress_bar.progress(float(TOTAL/len(packets_df)), text="Analysing packets...")

                        if prediction==0.0:
                            # st.info({'packet_type': reversed_label[int(0.0)]})
                            # Increment normal count
                            NORMAL+=1
                        
                        else:
                            
                            packet_data = packets_df.loc[[row]].copy()
                            label_data = pd.DataFrame([{'Attack Type': reversed_label[int(prediction)]}])
                            label_data.reset_index(drop=True, inplace=True)
                            packet_data.reset_index(drop=True, inplace=True)
                            attack_data = pd.concat([label_data, packet_data], axis=1)
                            display_data = pd.concat([display_data, attack_data], axis=0)
                            
                            st.write(display_data)
                            
                            
                            # Increment attack count
                            ATTACK+=1

                elapsed_time = time.perf_counter() - start_time

                attacks = []
                for i,j in zip(display_data['Attack Type'].unique(),
                          display_data['Attack Type'].value_counts(sort=False)):
                    attacks.append(f"{i}: {j}")

                st.success(f"All packets scanned successfully! 🚀")
                st.success(f"Total Packets: {TOTAL}")
                st.success(f"Normal Packets ✔: {NORMAL}")
                st.success(f"Attack Packets ⚠: {ATTACK}")
                st.success(f"Attack Types: {attacks}")
                st.success(f"Avg. prediction time (server side) 🧠: {(TOTAL_PRED_TIME/TOTAL):.10f}s\n")
                st.success(f"Overall run time ⌚: {elapsed_time:.3f}s")

                display_data.reset_index(inplace=True)
                csv = convert_df(display_data)
                st.download_button(label="Download Analysis File",
                                   data=csv,
                                   file_name=f"IoT_IDS_Report_{file.name}.csv",
                                   mime='text/csv')


            except Exception as e:
                st.error("Error: Please check the file or your network connection: \n" + str(e))
                # logger.info(f"An error occurred whilst attempting to call API:\n{e}")


if __name__ == "__main__":
    run()