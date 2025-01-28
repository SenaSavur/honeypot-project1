from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from analysis import (
    analyze_username_password,
    attack_distribution_by_hour,
    calculate_success_rate,
    analyze_top_attacking_countries
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:1000"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

@app.get("/")
def read_root():
    return {"message": "API başarıyla çalışıyor!"}

@app.get("/analyze/username-password")
def get_username_password_analysis():
    return analyze_username_password()

@app.get("/analyze/attack-distribution")
def get_attack_distribution():
    return attack_distribution_by_hour()

@app.get("/analyze/success-rate")
def get_success_rate():
    return calculate_success_rate()

@app.get("/analyze/top-attacking-countries")
def get_top_attacking_countries():
    return analyze_top_attacking_countries()
