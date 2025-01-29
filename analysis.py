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

# Her saldırı türünden kaç saldırı geldiğini analiz et
def analyze_attack_distribution():
    try:
        query = """
        SELECT 'brute_force' AS attack_type, COUNT(*) AS attack_count FROM brute_force
        UNION ALL
        SELECT 'dictionary_attack', COUNT(*) FROM dictionary_attack
        UNION ALL
        SELECT 'command_injection', COUNT(*) FROM command_injection
        UNION ALL
        SELECT 'file_download', COUNT(*) FROM file_download
        UNION ALL
        SELECT 'malware', COUNT(*) FROM malware
        UNION ALL
        SELECT 'pivoting', COUNT(*) FROM pivoting
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Saldırı türlerine ait veri bulunamadı."}

        return df.to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# En fazla yapılan saldırı türünü analiz et
def analyze_most_common_attack():
    try:
        df = analyze_attack_distribution()
        
        if "error" in df:
            return df  # Hata mesajını döndür

        df = pd.DataFrame(df)
        most_common_attack = df.sort_values(by="attack_count", ascending=False).iloc[0]

        return {
            "attack_type": most_common_attack["attack_type"],
            "count": int(most_common_attack["attack_count"])
        }

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# Saldırı türlerinin oranlarını hesapla
def analyze_attack_ratios():
    try:
        df = analyze_attack_distribution()
        
        if "error" in df:
            return df  # Hata mesajını döndür

        df = pd.DataFrame(df)
        total_attacks = df["attack_count"].sum()
        df["percentage"] = (df["attack_count"] / total_attacks) * 100

        return df[["attack_type", "percentage"]].to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# En çok kullanılan 5 username-password ikilisi(brute-force)
def analyze_top_brute_force_combinations():
    try:
        query = "SELECT username, password FROM brute_force"
        df = execute_query(query)

        if df.empty:
            return {"error": "Brute-force saldırılarına ait veri bulunamadı."}

        # En çok kullanılan kombinasyonları bul
        top_combinations = df.value_counts().reset_index(name="count")

        return top_combinations.head(5).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# En çok cowrie.login.success olan username-password ikilisi(brute-force)
def analyze_top_successful_brute_force():
    try:
        query = """
        SELECT username, password FROM brute_force
        WHERE eventid = 'cowrie.login.success'
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Başarılı brute-force girişlerine ait veri bulunamadı."}

        # En çok kullanılan kombinasyonu bul
        top_combination = df.value_counts().reset_index(name="count").iloc[0]

        return {
            "username": top_combination["username"],
            "password": top_combination["password"],
            "count": int(top_combination["count"])
        }

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

#En çok cowrie.login.failed olan username-password ikilisi(brute-force)
def analyze_top_failed_brute_force():
    try:
        query = """
        SELECT username, password FROM brute_force
        WHERE eventid = 'cowrie.login.failed'
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Başarısız brute-force girişlerine ait veri bulunamadı."}

        # En çok kullanılan kombinasyonu bul
        top_combination = df.value_counts().reset_index(name="count").iloc[0]

        return {
            "username": top_combination["username"],
            "password": top_combination["password"],
            "count": int(top_combination["count"])
        }

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# Saatlere göre brute-force saldırı yoğunluğu analizi
def analyze_brute_force_by_hour():
    try:
        query = "SELECT timestamp FROM brute_force"
        df = execute_query(query)

        if df.empty:
            return {"error": "Brute-force saldırılarına ait zaman verisi bulunamadı."}

        # Zamanı saat olarak gruplandır
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour"] = df["timestamp"].dt.hour
        time_counts = df["hour"].value_counts().sort_index()

        return time_counts.to_dict()

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
# En çok kullanılan 5 username-password ikilisi (`dictionary_attack`)
def analyze_top_dictionary_attack_combinations():
    try:
        query = "SELECT username, password FROM dictionary_attack"
        df = execute_query(query)

        if df.empty:
            return {"error": "Dictionary attack saldırılarına ait veri bulunamadı."}

        # En çok kullanılan kombinasyonları bul
        top_combinations = df.value_counts().reset_index(name="count")

        return top_combinations.head(5).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# En çok cowrie.login.success olan username-password ikilisi (`dictionary_attack`)
def analyze_top_successful_dictionary_attack():
    try:
        query = """
        SELECT username, password FROM dictionary_attack
        WHERE eventid = 'cowrie.login.success'
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Başarılı dictionary attack girişlerine ait veri bulunamadı."}

        # En çok kullanılan kombinasyonu bul
        top_combination = df.value_counts().reset_index(name="count").iloc[0]

        return {
            "username": top_combination["username"],
            "password": top_combination["password"],
            "count": int(top_combination["count"])
        }

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# En çok cowrie.login.failed olan username-password ikilisi (`dictionary_attack`)
def analyze_top_failed_dictionary_attack():
    try:
        query = """
        SELECT username, password FROM dictionary_attack
        WHERE eventid = 'cowrie.login.failed'
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Başarısız dictionary attack girişlerine ait veri bulunamadı."}

        # En çok kullanılan kombinasyonu bul
        top_combination = df.value_counts().reset_index(name="count").iloc[0]

        return {
            "username": top_combination["username"],
            "password": top_combination["password"],
            "count": int(top_combination["count"])
        }

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

# Saatlere göre dictionary attack saldırı yoğunluğu analizi(dictionary_attack)
def analyze_dictionary_attack_by_hour():
    try:
        query = "SELECT timestamp FROM dictionary_attack"
        df = execute_query(query)

        if df.empty:
            return {"error": "Dictionary attack saldırılarına ait zaman verisi bulunamadı."}

        # Zamanı saat olarak gruplandır
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour"] = df["timestamp"].dt.hour
        time_counts = df["hour"].value_counts().sort_index()

        return time_counts.to_dict()

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}