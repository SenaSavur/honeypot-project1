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
    
# En çok brute force saldırısı yapan 5 ülke
def analyze_top_brute_force_countries():
    try:
        query = """
        SELECT sc.attackfrom
        FROM brute_force bf
        JOIN session_connect sc ON bf.session = sc.session
        WHERE sc.attackfrom IS NOT NULL
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Brute force saldırılarına ait ülke verisi bulunamadı."}

        # En çok saldırı yapan ülkeleri bul
        top_countries = df["attackfrom"].value_counts().reset_index(name="count")
        top_countries.columns = ["country", "count"]

        return top_countries.head(5).to_dict(orient="records")

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
    
#En çok dictionary attack saldırısı yapan 5 ülke
def analyze_top_dictionary_attack_countries():
    try:
        query = """
        SELECT sc.attackfrom
        FROM dictionary_attack da
        JOIN session_connect sc ON da.session = sc.session
        WHERE sc.attackfrom IS NOT NULL
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Dictionary attack saldırılarına ait ülke verisi bulunamadı."}

        # En çok saldırı yapan ülkeleri bul
        top_countries = df["attackfrom"].value_counts().reset_index(name="count")
        top_countries.columns = ["country", "count"]

        return top_countries.head(5).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

def analyze_command_injection_by_hour(): #saatlere göre command_imjection yoğunluğu
    try:
        query = "SELECT timestamp FROM command_injection"
        df = execute_query(query)

        if df.empty:
            return {"error": "Command injection saldırılarına ait zaman verisi bulunamadı."}

        # Zamanı saat olarak gruplandır
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour"] = df["timestamp"].dt.hour
        time_counts = df["hour"].value_counts().sort_index()

        return time_counts.to_dict()

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

#En fazla tekrarlayan 3 input komutu(command-injection)
def analyze_top_command_injections():
    try:
        query = "SELECT input FROM command_injection WHERE input IS NOT NULL"
        df = execute_query(query)

        if df.empty:
            return {"error": "Command injection saldırılarına ait input verisi bulunamadı."}

        # En çok kullanılan inputları bul
        top_inputs = df["input"].value_counts().reset_index(name="count")
        top_inputs.columns = ["input", "count"]

        return top_inputs.head(3).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
#En çok command injection saldırısı yapan 5 ülke
def analyze_top_command_injection_countries():
    try:
        query = """
        SELECT sc.attackfrom
        FROM command_injection ci
        JOIN session_connect sc ON ci.session = sc.session
        WHERE sc.attackfrom IS NOT NULL
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Command injection saldırılarına ait ülke verisi bulunamadı."}

        # En çok saldırı yapan ülkeleri bul
        top_countries = df["attackfrom"].value_counts().reset_index(name="count")
        top_countries.columns = ["country", "count"]

        return top_countries.head(5).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
#Saatlere göre file download saldırı yoğunluğu analizi
def analyze_file_download_by_hour():
    try:
        query = "SELECT timestamp FROM file_download"
        df = execute_query(query)

        if df.empty:
            return {"error": "File download saldırılarına ait zaman verisi bulunamadı."}

        # Zamanı saat olarak gruplandır
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour"] = df["timestamp"].dt.hour
        time_counts = df["hour"].value_counts().sort_index()

        return time_counts.to_dict()

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

#En çok erişilmeye çalışılan 3 destfile(file_download)
def analyze_top_downloaded_files():
    try:
        query = "SELECT destfile FROM file_download WHERE destfile IS NOT NULL"
        df = execute_query(query)

        if df.empty:
            return {"error": "File download saldırılarına ait dosya verisi bulunamadı."}

        # En çok indirilmeye çalışılan dosyaları bul
        top_files = df["destfile"].value_counts().reset_index(name="count")
        top_files.columns = ["destfile", "count"]

        return top_files.head(3).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
#En çok file download saldırısı yapan 5 ülke
def analyze_top_file_download_countries():
    try:
        query = """
        SELECT sc.attackfrom
        FROM file_download fd
        JOIN session_connect sc ON fd.session = sc.session
        WHERE sc.attackfrom IS NOT NULL
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "File download saldırılarına ait ülke verisi bulunamadı."}

        # En çok saldırı yapan ülkeleri bul
        top_countries = df["attackfrom"].value_counts().reset_index(name="count")
        top_countries.columns = ["country", "count"]

        return top_countries.head(5).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
#Saatlere göre malware saldırı yoğunluğu analizi
def analyze_malware_by_hour():
    try:
        query = "SELECT timestamp FROM malware"
        df = execute_query(query)

        if df.empty:
            return {"error": "Malware saldırılarına ait zaman verisi bulunamadı."}

        # Zamanı saat olarak gruplandır
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour"] = df["timestamp"].dt.hour
        time_counts = df["hour"].value_counts().sort_index()

        return time_counts.to_dict()

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}

#En çok tekrar eden 3 filename(malware)
def analyze_top_malware_files():
    try:
        query = "SELECT filename FROM malware WHERE filename IS NOT NULL"
        df = execute_query(query)

        if df.empty:
            return {"error": "Malware saldırılarına ait dosya verisi bulunamadı."}

        # En çok kullanılan filename'leri bul
        top_filenames = df["filename"].value_counts().reset_index(name="count")
        top_filenames.columns = ["filename", "count"]

        return top_filenames.head(3).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
#En çok malware saldırısı yapan 5 ülke
def analyze_top_malware_countries():
    try:
        query = """
        SELECT sc.attackfrom
        FROM malware m
        JOIN session_connect sc ON m.session = sc.session
        WHERE sc.attackfrom IS NOT NULL
        """
        df = execute_query(query)

        if df.empty:
            return {"error": "Malware saldırılarına ait ülke verisi bulunamadı."}

        # En çok saldırı yapan ülkeleri bul
        top_countries = df["attackfrom"].value_counts().reset_index(name="count")
        top_countries.columns = ["country", "count"]

        return top_countries.head(5).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
#En fazla kullanılan protocoller ve sayıları
def analyze_top_protocols():
    try:
        query = "SELECT protocol FROM session_connect WHERE protocol IS NOT NULL"
        df = execute_query(query)

        if df.empty:
            return {"error": "Session connect tablosunda protocol verisi bulunamadı."}

        # En çok kullanılan 2 protokolü bul
        top_protocols = df["protocol"].value_counts().reset_index(name="count")
        top_protocols.columns = ["protocol", "count"]

        return top_protocols.head(2).to_dict(orient="records")

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}
    
# Saldırganların brute_force ve dictionary_attack için ayrı ayrı login başarı oranları
def analyze_attacker_login_success_separately():
    try:
        # Brute Force için login başarısı analizi
        brute_force_query = """
        SELECT eventid FROM brute_force WHERE eventid IN ('cowrie.login.success', 'cowrie.login.failed')
        """
        brute_force_df = execute_query(brute_force_query)

        brute_success = brute_force_df["eventid"].value_counts().get("cowrie.login.success", 0)
        brute_failed = brute_force_df["eventid"].value_counts().get("cowrie.login.failed", 0)
        brute_total = brute_success + brute_failed
        brute_success_rate = f"%{round((brute_success / brute_total) * 100, 2)}" if brute_total > 0 else "%0"

        # Dictionary Attack için login başarısı analizi
        dictionary_query = """
        SELECT eventid FROM dictionary_attack WHERE eventid IN ('cowrie.login.success', 'cowrie.login.failed')
        """
        dictionary_df = execute_query(dictionary_query)

        dict_success = dictionary_df["eventid"].value_counts().get("cowrie.login.success", 0)
        dict_failed = dictionary_df["eventid"].value_counts().get("cowrie.login.failed", 0)
        dict_total = dict_success + dict_failed
        dict_success_rate = f"%{round((dict_success / dict_total) * 100, 2)}" if dict_total > 0 else "%0"

        return {
            "brute_force": {
                "successful_logins": int(brute_success),
                "failed_logins": int(brute_failed),
                "success_rate": brute_success_rate
            },
            "dictionary_attack": {
                "successful_logins": int(dict_success),
                "failed_logins": int(dict_failed),
                "success_rate": dict_success_rate
            }
        }

    except Exception as e:
        return {"error": f"Bir hata oluştu: {str(e)}"}