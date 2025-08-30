from fastapi import FastAPI
import joblib
from pydantic import BaseModel

app = FastAPI()

# Load model + vectorizer
model = joblib.load("url_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

class URLItem(BaseModel):
    url: str

@app.get("/")
def home():
    return {"message": "Malicious URL Detection API is running!"}

@app.post("/predict")
def predict(item: URLItem):
    features = vectorizer.transform([item.url])
    prediction = model.predict(features)[0]
    result = "malicious" if prediction == 1 else "safe"
    return {"url": item.url, "prediction": result}
