"""
This module contains the API service for predicting network attack based on network packet data supplied by user on web UI
"""

import os
import time
import asyncio
import concurrent.futures
from multiprocessing import Process
import joblib
import zipfile
from fastapi import FastAPI, Request, File, UploadFile, Response
import uvicorn
import pandas as pd
import numpy as np
from pydantic import BaseModel
import xgboost as xgb
import pyshark
from src.features.build_features import preprocess
from src.data.packet_streamer import pcap_stream
from src.utils.backend_log_config import backend as logger
# Frontend
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates



# Initialize FastAPI
app = FastAPI(title='Cloud Based IDS for IoT Networks',
              version='0.1.0',
              description=''
              )

# Mount the static files directory
app.mount("/static", StaticFiles(directory="./static"), name="static")
templates = Jinja2Templates(directory="./templates")

# Load model
MODELS_DIR = './models/'
model = xgb.Booster()
model.load_model(MODELS_DIR+'xgb_model.bin')


# Data Validation
class Data(BaseModel):
    model: str
    data: dict
    packet: dict


# API test endpoint
@app.get('/test')
def test_page():
    """
    Test endpoint which can be used to test the availability of the application.
    """
    logger.info("API service tested")
    return {'message': 'System is healthy'}

# Home page
@app.get('/', response_class=HTMLResponse)
async def home_page(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

# File upload endpoint
@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(None)):
    filename = file.filename if file else "No file chosen"
    success_message = ""

    try:
        if filename:
            # File was selected and submit button was clicked, save the file
            main_directory = os.path.dirname(os.path.abspath(__file__))
            directory_path = os.path.join(main_directory, "temp")

            # Clear all files in temp dir
            # Get the list of files in the directory
            file_list = os.listdir(directory_path)

            # Iterate over the files and delete them
            for file_name in file_list:
                if ".gitignore" not in file_name:
                    file_path = os.path.join(directory_path, file_name)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        logger.info(f"Deleted file: {file_path}")

            # Define new file file path
            file_path = os.path.join(directory_path, filename)

            # Create the directory if it does not exist
            if not os.path.exists(directory_path):
                os.makedirs(directory_path)

            # Write the pcap file
            with open(file_path, "wb") as f:
                contents = await file.read()
                f.write(contents)
            logger.info(f"File '{filename}' uploaded and saved to: {file_path}")
            success_message = f"{filename} Uploaded successfully!"
    except Exception as e:
        logger.warning(f"File upload failed: {e}")
        success_message = f"File upload failed: {e}"

    return {"filename": file_path, "success_message": success_message}

# File processing endpoint
def process_pcap(filename):
    print('running data parse')
    temp_df = pd.DataFrame()
    print('dataframe created')

    # Get temp dir
    main_directory = os.path.dirname(os.path.abspath(__file__))
    directory_path = os.path.join(main_directory, "temp")

    # Define new file file path
    file_path = os.path.join(directory_path, filename)

    for i in pcap_stream(file_path):
        temp_df = pd.concat([temp_df, i], axis=0)
    print('\nPreprocessing data')

    # Define unprocessed csv file file path
    unprocessed_csv_file_path = os.path.join(directory_path, str(filename[:-5]+'unprocessed.csv'))
    temp_df.to_csv(unprocessed_csv_file_path, index=False, header=True, mode='w')

    temp_df = preprocess(temp_df, train=False)

    # Define new csv file file path
    csv_file_path = os.path.join(directory_path, str(filename[:-5]+'.csv'))
    np.savetxt(csv_file_path, temp_df, delimiter=',')
    print('process complete')

@app.post("/process")
def process_file(data: dict):
    try:
        filename = data['filename']
        p = Process(target=process_pcap, args=(filename,))
        p.start()
        p.join()
        return {'response': "Processing complete!"}
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        return {'response': f"Processing failed: \n{e}"}

# Processed file retrieval endpoint
@app.post("/retrieve")
def download_csv(data: dict):
    filename = data['filename']
    # Get temp dir
    main_directory = os.path.dirname(os.path.abspath(__file__))
    directory_path = os.path.join(main_directory, "temp")

    # Define new file file path
    csv_file_path = os.path.join(directory_path, str(filename[:-5]+'.csv'))
    unprocessed_csv_file_path = os.path.join(directory_path, str(filename[:-5]+'unprocessed.csv'))

    file_paths = [csv_file_path, unprocessed_csv_file_path]

    if file_paths:
        try:
            # Create a zip archive containing the files
            zip_file_path = os.path.join(directory_path, str('files.zip'))
            with zipfile.ZipFile(zip_file_path, 'w') as zip_file:
                for file_path in file_paths:
                    zip_file.write(file_path)

            # Set the appropriate HTTP response headers
            
            with open(zip_file_path, 'rb') as zip_file:
                content = zip_file.read()

            response = Response(content=content, media_type='application/zip')
            response.headers['Content-Disposition'] = 'attachment; filename="files.zip"'

            return response

        except Exception as e:
            return {"response": f"Error: {e}"}

    return {"response": "Error: File path not provided."}

# Prediction endpoint
@app.post("/predict")
def predict(packet: dict):
    """
    Takes dictionary containing specification of desired prediction model and user credit card data as input and
    returns prediction result as output.
    Args:
        data(dict): data from web UI

    Returns:
        result(float): float value of percentage default probability
    """
    logger.info("prediction request received")
    logger.info("preprocessing web UI data")

    try:
        packet = packet["data"]
        packet = pd.DataFrame([packet])
        data_point = xgb.DMatrix(packet)
    except Exception as exc:
        logger.exception(f"Error preprocessing data:\n{exc}")

    logger.info("generating prediction")
    try:
        start_time = time.perf_counter()
        result: float = float(model.predict(data_point))
        elapsed_time = time.perf_counter()-start_time
        packet = {"result": result, "time": elapsed_time}

        logger.info(f"sending result '{result}'  to frontend")
    except Exception as exc:
        logger.exception(f"Error generating prediction:\n{exc}")
    return packet


if __name__ == '__main__':
    logger.info("API service running")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)