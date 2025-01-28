import pandas as pd
from sqlalchemy import create_engine
from database import get_database_connection
from utils import get_country_from_ip
import time

# SQL sorgusunu çalıştırma ve DataFrame döndürme
def execute_query(query):
    engine = get_database_connection()
    with engine.connect() as connection:
        return pd.read_sql(query, connection)

# Username-password analizi
def analyze_username_password():
    query = "SELECT username, passwordd FROM attacks"
    df = execute_query(query)
    top_combinations = df.value_counts().reset_index(name='count')
    return top_combinations.head(10).to_dict(orient="records")

# Saatlere göre saldırı yoğunluğu analizi
def attack_distribution_by_hour():
    query = "SELECT timestamp FROM attacks"
    df = execute_query(query)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    time_counts = df['hour'].value_counts().sort_index()
    return time_counts.to_dict()

# Login başarı oranı analizi
def calculate_success_rate():
    try:
        query = "SELECT eventid FROM attacks WHERE eventid IN ('cowrie.login.success', 'cowrie.login.failed')"
        df = execute_query(query)

        if df.empty:
            return {"error": "Veritabanında başarı ve başarısızlık bilgisi bulunamadı."}

        success_count = int(df['eventid'].value_counts().get('cowrie.login.success', 0))
        failed_count = int(df['eventid'].value_counts().get('cowrie.login.failed', 0))
        total_attempts = success_count + failed_count
        success_rate = float((success_count / total_attempts) * 100 if total_attempts > 0 else 0)

        return {
            "success_count": success_count,
            "failed_count": failed_count,
            "success_rate": round(success_rate, 2)
        }
    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
# En çok saldırı yapan 10 ülke analiz
def analyze_top_attacking_countries():
    try:
        query = "SELECT attackfrom FROM attacks"
        df = execute_query(query)
        
        if df.empty or 'attackfrom' not in df.columns:
            return {"error": "Veritabanında ülke bilgisi bulunamadı."}

        country_counts = df['attackfrom'].value_counts().head(10)
        top_countries = country_counts.reset_index(name='count')
        top_countries.columns = ['country', 'count']

        return top_countries.to_dict(orient="records")
    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
