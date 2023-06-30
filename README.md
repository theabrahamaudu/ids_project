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