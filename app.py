# api.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import uvicorn
import os

# Pick which model file to use
MODEL_PATH = os.environ.get("MODEL_PATH", "url_model_tldfreq.pkl")

app = FastAPI(title="Malicious URL Detection API")

# Load model at startup
model = None
encoder = None

@app.on_event("startup")
def load_model():
    global model, encoder
    if not os.path.exists(MODEL_PATH):
        raise RuntimeError(f"Model not found at {MODEL_PATH}")
    try:
        bundle = joblib.load(MODEL_PATH)
        model = bundle["model"]
        encoder = bundle["encoder"]
    except Exception as e:
        raise RuntimeError(f"Failed to load model: {str(e)}")

# Request schema
class URLItem(BaseModel):
    url: str

@app.get("/")
def home():
    return {"message": "Malicious URL Detection API is running"}

@app.post("/predict")
def predict_url(item: URLItem):
    if model is None or encoder is None:
        raise HTTPException(status_code=500, detail="Model not loaded")

    try:
        pred = model.predict([item.url])[0]
        label = encoder.inverse_transform([pred])[0]
        return {
            "url": item.url,
            "prediction": label
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
