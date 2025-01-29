from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from analysis import (
    analyze_attack_distribution, 
    analyze_most_common_attack,  
    analyze_attack_ratios,  
    analyze_top_brute_force_combinations,
    analyze_top_successful_brute_force, 
    analyze_top_failed_brute_force,
    analyze_brute_force_by_hour,
    analyze_top_dictionary_attack_combinations,
    analyze_top_successful_dictionary_attack,  
    analyze_top_failed_dictionary_attack,  
    analyze_dictionary_attack_by_hour 
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

@app.get("/")
def read_root():
    return {"message": "API başarıyla çalışıyor!"}

# Her saldırı türünün sayısını getir
@app.get("/analyze/attack-distribution")
def get_attack_distribution():
    return analyze_attack_distribution()

#En fazla yapılan saldırı türünü getir
@app.get("/analyze/most-common-attack")
def get_most_common_attack():
    return analyze_most_common_attack()

#Her saldırı türünün oranlarını getir
@app.get("/analyze/attack-ratios")
def get_attack_ratios():
    return analyze_attack_ratios()

# En çok kullanılan 5 username-password kombinasyonu(brute-force)
@app.get("/analyze/brute-force/top-combinations")
def get_top_brute_force_combinations():
    return analyze_top_brute_force_combinations()

# En çok cowrie.login.success olan kombinasyon(brute-force)
@app.get("/analyze/brute-force/top-successful")
def get_top_successful_brute_force():
    return analyze_top_successful_brute_force()

# En çok cowrie.login.failed olan kombinasyon(brute-force)
@app.get("/analyze/brute-force/top-failed")
def get_top_failed_brute_force():
    return analyze_top_failed_brute_force()

# Saatlere göre brute-force saldırı yoğunluğu(brute-force)
@app.get("/analyze/brute-force/by-hour")
def get_brute_force_by_hour():
    return analyze_brute_force_by_hour()

# En çok kullanılan 5 username-password kombinasyonu (dictionary_attack)
@app.get("/analyze/dictionary-attack/top-combinations")
def get_top_dictionary_attack_combinations():
    return analyze_top_dictionary_attack_combinations()

# En çok cowrie.login.success olan kombinasyon (dictionary_attack)
@app.get("/analyze/dictionary-attack/top-successful")
def get_top_successful_dictionary_attack():
    return analyze_top_successful_dictionary_attack()

# En çok cowrie.login.failed olan kombinasyon (dictionary_attack)
@app.get("/analyze/dictionary-attack/top-failed")
def get_top_failed_dictionary_attack():
    return analyze_top_failed_dictionary_attack()

# Saatlere göre dictionary attack saldırı yoğunluğu(dictionary_attack)
@app.get("/analyze/dictionary-attack/by-hour")
def get_dictionary_attack_by_hour():
    return analyze_dictionary_attack_by_hour()