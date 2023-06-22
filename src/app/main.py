"""
This module contains the API service for predicting network attack based on network packet data supplied by user on web UI
"""

import os
import time
import asyncio
import concurrent.futures
from multiprocessing import Process
import joblib
from fastapi import FastAPI, Request, File, UploadFile
import uvicorn
import pandas as pd
import numpy as np
from pydantic import BaseModel
from xgboost import DMatrix
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
app.mount("/static", StaticFiles(directory="./src/app/static"), name="static")
templates = Jinja2Templates(directory="./src/app/templates")

# Load model
MODEL_DIR = './models/xgb_model.joblib'
model = joblib.load(MODEL_DIR)


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
            file_path = os.path.join(main_directory, "temp", filename)
            with open(file_path, "wb") as f:
                contents = await file.read()
                f.write(contents)
            logger.info(f"File '{filename}' uploaded and saved to: {file_path}")
            success_message = f"{filename} Uploaded successfully!"
    except Exception as e:
        logger.warning(f"File upload failed: {e}")
        success_message = f"File upload failed: {e}"

    return templates.TemplateResponse("home.html", {"request": request, "filename": filename, "success_message": success_message})

# File processing endpoint

def process_pcap(filename):
    print('running data parse')
    temp_df = pd.DataFrame()
    print('dataframe created')
    for i in pcap_stream(filename):
        temp_df = pd.concat([temp_df, i], axis=0)
    print('\nPreprocessing data')
    temp_df = preprocess(temp_df, train=False)
    np.savetxt(str(filename[:-5]+'.csv'), temp_df, delimiter=',')
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
        data_point = DMatrix(packet)
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
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)