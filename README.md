IoT IDS App
==============================

Cloud-Based AI Intrusion Detection System for IoT Networks

Project Organization
------------

    ├── LICENSE
    ├── Makefile           <- Makefile with commands like `make data` or `make train` (Unused)
    ├── README.md          <- The top-level README for developers using this project.
    │
    ├── main.py            <- Module to run data transformation and model training pipeline.
    ├── app.py             <- Module to fire up model API service.
    ├── streamlit_app.py   <- Module to run IDS web app.
    │
    ├── data
    │   ├── external       <- Data from third party sources.
    │   ├── interim        <- Intermediate data that has been transformed.
    │   ├── labelled       <- Transformed data that has been labelled.
    │   ├── processed      <- The final, canonical data sets for modeling.
    │   └── raw            <- The original, immutable data dump.
    │
    ├── docs               <- A default Sphinx project; see sphinx-doc.org for details
    │
    ├── models             <- Trained and serialized models and model summaries
    │
    ├── notebooks          <- Jupyter notebooks and experimental .py scripts. 
    │
    ├── references         <- Data dictionaries, manuals, and all other explanatory materials.
    │
    ├── reports            <- Generated analysis as HTML, PDF, LaTeX, etc.
    │   └── figures        <- Generated graphics and figures to be used in reporting
    │
    ├── requirements.txt   <- The requirements file for reproducing the environment
    │
    ├── setup.py           <- makes project pip installable (pip install -e .) so src can be imported
    ├── src                <- Source code for use in this project.
    │   ├── __init__.py    <- Makes src a Python module
    │   │
    │   ├── data           <- Scripts to generate data
    │   │   └── data_filters.py
    │   │   └── load_n_filter.py
    │   │   └── packet_streamer.py
    │   │   └── pcap_to_csv.py
    │   │
    │   ├── features       <- Scripts to turn raw data into features for modeling
    │   │   └── build_features.py
    │   │
    │   ├── models         <- Scripts to train models and then use trained models to make
    │   │   │                 predictions
    │   │   └── train_model.py
    │   │
    │   ├── utils         <- Utility scripts used across the project
    │   │   └── backend_log_config.py
    │   │   └── frontend_log_config.py
    │   │   └── pipeline_log_config.py
    │   │
    │   └── visualization  <- Scripts to create exploratory and results oriented visualizations
    │       └── visualize.py
    │
    └── tox.ini            <- tox file with settings for running tox; see tox.readthedocs.io


--------
This repository contains an AI-powered cloud-based intrusion detection system (IDS) designed specifically for IoT networks. The system leverages an XGB (Extreme Gradient Boosting) model to detect and classify various types of attacks, ensuring the security and integrity of IoT environments.

## Dataset Overview
The dataset used in this system consists of several types of attacks commonly encountered in IoT networks:

- MITM-ARPSpoofing-n(1~6)-dec.pcap: This dataset includes traffic with both benign and Man-in-the-Middle (ARP spoofing) attacks.
- DoS-SYNFlooding-n(1~6)-dec.pcap: Contains traffic with both benign and Denial of Service (SYN flooding) attacks.
- Scan-HostPort-n(1~6)-dec.pcap: Includes traffic with both benign and scan (host and port scan) attacks.
- Scan-PortOS-n(1~6)-dec.pcap: Contains traffic with both benign and scan (port and OS scan) attacks.
- Mirai-UDPFlooding-n(1~4)-dec.pcap, Mirai-ACKFlooding-n(1~4)-dec.pcap, Mirai-HTTPFlooding-n(1~4)-dec.pcap: These datasets include traffic with both benign and three typical attacks (UDP/ACK/HTTP Flooding) executed by zombie PCs compromised by the Mirai malware.
- Mirai-HostBruteforce-n(1~5)-dec.pcap: Contains traffic with both benign and the initial phase of the Mirai malware, including host discovery and Telnet brute-force attacks.

## System Architecture
The system is designed to streamline the training and inference pipelines, ensuring code reusability and consistency in outcomes. Here is an overview of the system architecture:

![image](https://github.com/theabrahamaudu/ids_project/assets/82980669/1f247c2b-2bdc-4fa3-8a79-bdca7f427e40)

### Training Pipeline
The packet data is first ingested by the ingestion module, which reads the packets into dataframes for further processing. The preprocessing module performs necessary transformations to prepare the data for model training and validation. During the model training phase, a decision is made whether to save the trained model or retrain it based on human judgment of its performance.

### Inference Pipeline
The API module loads the saved model and provides endpoints for user interaction. Users can upload raw data, which is then processed and made available for retrieval. Requests can be made to analyze and classify the processed data points based on the recognized attack classes in the model. The user interface facilitates interactive communication with the API, enabling packet analysis and the option to download analysis reports for future reference by network security personnel.

### Real-time Monitoring
The system architecture includes the capability to establish remote connections to networks and stream packets in real-time to the IDS. This enables active monitoring of network packets and immediate detection of intrusions as they occur.

### Simulation of Real-time Data
During the development phase, due to limitations in accessing a real-time IoT system, the data ingestion module was configured to handle bulk data instead. To simulate the streaming process to the prediction endpoint, the module mimicked the behavior of receiving data as if it were being streamed live from a remote location. This approach ensured that the system could be tested and evaluated even without real-time data availability.

### Deployment and User Interface
To ensure component separation, the user interface and API modules are deployed on different servers. The API engine is deployed on an Amazon Web Services (AWS) Elastic Compute Cluster (EC2) instance, while the user interface communicates with the API through a secure HTTPS connection. The user interface provides real-time updates to the user by displaying newly discovered attack packets in a dynamic window. These attack packets are presented in a human-readable format, along with their corresponding packet parameters.

After the analysis process is completed, the generated data is made available for download in CSV format. This enables network security personnel to perform in-depth analysis and make informed decisions regarding network security based on the specific details of the flagged packets.

### Performance Metrics
The final XGB (Extreme Gradient Boosting) model achieved impressive performance metrics:

- F1 macro avg: 0.997
- F1 weighted avg: 1.0
- Class 0.0: 1.0
- Class 1.0: 1.0
- Class 10.0: 0.973
- Class 2.0: 1.0
- Class 3.0: 0.995
- Class 4.0: 1.0
- Class 5.0: 1.0
- Class 6.0: 1.0
- Class 7.0: 1.0
- Class 8.0: 1.0
- Class 9.0: 0.999
- Inference Time per Data Point: 1.0665294169455698e-05s
- Training Time: 151.546875s

--------

## Getting Started
To use the IoT IDS App, visit <a href="https://iotids.streamlit.app/">IOT IDS App</a>.
###### P.S: Server is not always up as the app is in beta 

Steps:
- Select and upload a PCAP or PCAPNG file containing network packet data for an IoT network
- Click the `Process` button to toggle file processing
- Click `Activate IDS` to initialize packet analysis
- Click `Download Analysis File` to download human readable CSV of flagged packets for further analysis
--------
## Experimenting 
### Requirements
- Windows 10, Ubuntu or any other suitable OS
- Python >=3.10
- Wireshark/tshark

### Reproduce Experiment
- Create a new virtual environment
- run:  ```git clone https://github.com/theabrahamaudu/ids_project.git```  
- install requirements:  ```pip install -r requirements.txt```
- Download the training dataset <a href="https://ieee-dataport.org/open-access/iot-network-intrusion-dataset">here</a>.
- On your OS file explorer, move the dataset zip file to `path/to/.../ids_project/data/external/` and unzip the file in the directory
- Run the preprocessing and model training pipeline:  ```python main.py``` <a small style="color:yellow"> N.B: This step could take a while (a.k.a hours)</a>.
- Start the API Service: ```python app.py```
- Open the `streamlit_app.py` module and swap the commenting between local and deployment `server` variable [ln 37,38], then open another terminal and run: ```streamlit run streamlit_app.py```

### Reproduce Deployment
#### API Server Side
- Create AWS EC2 instance (Ubuntu)
- Open the `streamlit_app.py` module and swap the commenting between local and deployment `server` variable [ln 37,38] back to the server mode and replace the `server` IP with the `Public IP` of your new EC2 instance
- Create a new public GitHub repository
- Push the code to the new repository
- Clone the new repository on the EC2 instance
- Setup app:
    - Navigate to the app directory: ```cd [name_of_project_repo]```
    - Update the EC2 instance: ```sudo apt-get update```
    - Install python ```sudo apt install python3-pip```
    - Install requirements ```pip3 install -r requirements.txt --no-cache-dir```
    - run the app to be sure all is good: ```python3 app.py```
- Configure NGINX for the app as described <a href="https://lcalcagni.medium.com/deploy-your-fastapi-to-aws-ec2-using-nginx-aa8aa0d85ec7">here</a> [Skip to **Nginx configuration** section].
- Install tshark: ```sudo apt install tshark```

#### Streamlit App
- Create a <a href="streamlit.io">streamlit.io</a> account using your github account.
- Create a streamlit app using the new repo you created for this app.
- Use `streamlit_app.py` as the main app.
- Click `Advanced...` and set python version to `Python 3.10` before firing it up.

*Congratulations! 🎈* You have now successfully recreated the IoT IDS App.