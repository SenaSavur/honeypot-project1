from analysis import (
    analyze_username_password,
    attack_distribution_by_hour,
    calculate_success_rate,
)

from fastapi import FastAPI

app = FastAPI()

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
