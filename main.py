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
    analyze_dictionary_attack_by_hour,
    analyze_command_injection_by_hour,
    analyze_top_command_injections,
    analyze_file_download_by_hour,
    analyze_top_downloaded_files,
    analyze_malware_by_hour,
    analyze_top_malware_files,
    analyze_top_protocols,
    analyze_top_brute_force_countries,
    analyze_top_command_injection_countries,
    analyze_top_dictionary_attack_countries,
    analyze_top_file_download_countries,
    analyze_top_malware_countries,
    analyze_attacker_login_success_separately
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

#En çok brute force saldırısı yapan 5 ülke
@app.get("/analyze/brute-force/top-countries")
def get_top_brute_force_countries():
    return analyze_top_brute_force_countries()

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

# Saatlere göre dictionary attack saldırı yoğunluğu
@app.get("/analyze/dictionary-attack/by-hour")
def get_dictionary_attack_by_hour():
    return analyze_dictionary_attack_by_hour()

#En çok dictionary attack saldırısı yapan 5 ülke
@app.get("/analyze/dictionary-attack/top-countries")
def get_top_dictionary_attack_countries():
    return analyze_top_dictionary_attack_countries()

# Saatlere göre command injection saldırı yoğunluğu
@app.get("/analyze/command-injection/by-hour")
def get_command_injection_by_hour():
    return analyze_command_injection_by_hour()

# En fazla tekrarlayan 3 input komutu- command injection
@app.get("/analyze/command-injection/top-inputs")
def get_top_command_injections():
    return analyze_top_command_injections()

# En çok command injection saldırısı yapan 5 ülke
@app.get("/analyze/command-injection/top-countries")
def get_top_command_injection_countries():
    return analyze_top_command_injection_countries()

#Saatlere göre file download saldırı yoğunluğu
@app.get("/analyze/file-download/by-hour")
def get_file_download_by_hour():
    return analyze_file_download_by_hour()

# En çok indirilmeye çalışılan 3 dosya(file_download)
@app.get("/analyze/file-download/top-files")
def get_top_downloaded_files():
    return analyze_top_downloaded_files()

#En çok file download saldırısı yapan 5 ülke
@app.get("/analyze/file-download/top-countries")
def get_top_file_download_countries():
    return analyze_top_file_download_countries()

#Saatlere göre malware saldırı yoğunluğu
@app.get("/analyze/malware/by-hour")
def get_malware_by_hour():
    return analyze_malware_by_hour()

#En çok tekrarlanan 3 filename(malware)
@app.get("/analyze/malware/top-files")
def get_top_malware_files():
    return analyze_top_malware_files()

#En çok malware saldırısı yapan 5 ülke
@app.get("/analyze/malware/top-countries")
def get_top_malware_countries():
    return analyze_top_malware_countries()

#En çok kullanılan portlar
@app.get("/analyze/session-connect/top-protocols")
def get_top_protocols():
    return analyze_top_protocols()

#brute-force ve dictionary-attack için login yüzdeleri
@app.get("/analyze/attacker-login-success")
def get_attacker_login_success():
    return analyze_attacker_login_success_separately()