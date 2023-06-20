"""
This module contains the API service for predicting credit card default based on data supplied by user on web UI
"""
import time
import joblib
from fastapi import FastAPI, Request
import uvicorn
import pandas as pd
from pydantic import BaseModel
from xgboost import DMatrix
from src.features.build_features import preprocess
from src.utils.backend_log_config import backend as logger
# Frontend
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
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

# File selection endpoint
@app.post("/select_file")
async def upload_file(request: Request):
    form = await request.form()
    file = form["file-upload"]
    filename = file.filename if file else "No file chosen"
    return templates.TemplateResponse("index.html", {"request": request, "filename": filename})

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
        data_point = preprocess(packet, train=False)
        data_point = DMatrix(data_point)
    except Exception as exc:
        logger.exception(f"Error preprocessing data:\n{exc}")

    logger.info("generating prediction")
    try:
        start_time = time.perf_counter()
        result: float = float(model.predict(data_point))
        elapsed_time = time.perf_counter()-start_time
        packet = {"result": result, "time": elapsed_time}

        logger.info("sending result to frontend")
    except Exception as exc:
        logger.exception(f"Error generating prediction:\n{exc}")
    return packet


if __name__ == '__main__':
    logger.info("API service running")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)