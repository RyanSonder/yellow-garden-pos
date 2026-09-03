from fastapi import FastAPI

from fastapi.middleware.cors import CORSMiddleware

from .routes import router

app = FastAPI(title="POS System")

app.include_router(router)


@app.get("/")
def root():
    return {"message": "POS API is running"}


app = FastAPI(title="POS System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {"message": "POS API is running"}