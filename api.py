# # api.py
# from fastapi import FastAPI, HTTPException
# from pydantic import BaseModel
# import joblib
# import uvicorn
# import os

# # Pick which model file to use
# MODEL_PATH = os.environ.get("MODEL_PATH", "url_model_tldfreq.pkl")

# app = FastAPI(title="Malicious URL Detection API")

# # Load model at startup
# model = None

# @app.on_event("startup")
# def load_model():
#     global model
#     if not os.path.exists(MODEL_PATH):
#         raise RuntimeError(f"Model not found at {MODEL_PATH}")
#     try:
#         model = joblib.load(MODEL_PATH)
#     except Exception as e:
#         raise RuntimeError(f"Failed to load model: {str(e)}")

# # Request schema
# class URLItem(BaseModel):
#     url: str

# @app.get("/")
# def home():
#     return {"message": "Malicious URL Detection API is running"}

# @app.post("/predict")
# def predict_url(item: URLItem):
#     if model is None:
#         raise HTTPException(status_code=500, detail="Model not loaded")

#     try:
#         prediction = model.predict([item.url])[0]
#         return {
#             "url": item.url,
#             "malicious": bool(prediction)  # 1 → True, 0 → False
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)

