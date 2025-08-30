import joblib
from fastapi import FastAPI
from pydantic import BaseModel

# Load both model and vectorizer
model = joblib.load("url_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

app = FastAPI()

class URLItem(BaseModel):
    url: str

@app.post("/predict")
def predict_url(item: URLItem):
    features = vectorizer.transform([item.url])
    prediction = model.predict(features)[0]
    result = "malicious" if prediction == 1 else "safe"
    return {"url": item.url, "prediction": result}
