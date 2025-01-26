import pandas as pd
import time
from sqlalchemy import text
from database import get_database_connection
from utils import get_country_from_ip


def update_attackfrom():
    ip_cache = {}  # Önceden çekilen IP'ler için bir cache

    try:
        # Veritabanından 'attackfrom' sütunu boş olan kayıtları çek
        query = "SELECT src_ip FROM attacks WHERE attackfrom IS NULL"
        engine = get_database_connection()
        df = pd.read_sql(query, engine)

        if df.empty:
            print("Güncellenecek kayıt bulunamadı.")
            return

        # Veritabanına bağlantı aç
        with engine.connect() as connection:
            for _, row in df.iterrows():
                ip = row['src_ip']

                # Cache kontrolü
                if ip in ip_cache:
                    location = ip_cache[ip]
                else:
                    # API'den konum bilgisini al
                    location = get_country_from_ip(ip)
                    ip_cache[ip] = location

                # Veritabanını güncelle
                if location != "Unknown":
                    update_query = text("""
                    UPDATE attacks
                    SET attackfrom = :location
                    WHERE src_ip = :ip
                    """)
                    connection.execute(update_query, {"location": location, "ip": ip})

                # API limitleri için bekleme süresi
                time.sleep(1)

        print("attackfrom sütunu başarıyla güncellendi.")
    except Exception as e:
        print(f"Bir hata oluştu: {e}")


if __name__ == "__main__":
    update_attackfrom()
