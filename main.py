from fastapi import FastAPI, Depends
import models
from database import engine
from routers import logs, detect
from routers import alerts

app= FastAPI()

models.Base.metadata.create_all(bind=engine)

app.include_router(detect.router)
app.include_router(logs.router)
app.include_router(alerts.router)

@app.get("/")
def root():
    return {"message": "API is running"}