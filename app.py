# from fastapi import FastAPI
# import joblib
# import uvicorn
# from pydantic import BaseModel

# app = FastAPI()

# # Load trained model
# model = joblib.load("url_model_tldfreq.pkl")

# @app.get("/")
# def home():
#     return {"message": "Malicious URL Detection API is running"}


# class URLItem(BaseModel):
#     url: str

# @app.post("/predict")
# def predict_url(item: URLItem):
#     prediction = model.predict([item.url])[0]
#     return {"url": item.url, "malicious": bool(prediction)}

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)
