import pandas as pd
import time
from sqlalchemy import text
from database import get_database_connection
from utils import get_country_from_ip


def update_attackfrom():
    ip_cache = {}  # Önceden çekilen IP'ler için bir cache

    try:
        # Veritabanından 'attackfrom' sütunu boş olan ve unique IP adreslerini çek
        query = "SELECT DISTINCT src_ip FROM attacks WHERE attackfrom IS NULL"
        engine = get_database_connection()
        df = pd.read_sql(query, engine)

        if df.empty:
            print("Güncellenecek kayıt bulunamadı.")
            return

        # IP adreslerini liste olarak al
        ip_list = df['src_ip'].tolist()

        # TEST AMAÇLI: Belirli bir IP adresi için güncelleme sorgusunu çalıştır
        try:
            with engine.connect() as connection:
                update_query = text("""
                UPDATE attacks
                SET attackfrom = :location
                WHERE src_ip = :ip
                """)
                result = connection.execute(update_query, {"location": "Test Location", "ip": "39.170.91.56"})
                print(f"Test amaçlı güncellenen satır sayısı: {result.rowcount}")
        except Exception as e:
            print(f"Test sorgusu sırasında bir hata oluştu: {e}")

        # ASIL İŞLEM: Tüm kayıtlar için güncelleme
        with engine.connect() as connection:
            transaction = connection.begin()  # Transaction başlat
            try:
                for ip in ip_list:
                    # Cache kontrolü
                    if ip in ip_cache:
                        location = ip_cache[ip]
                    else:
                        # API'den konum bilgisini al
                        location = get_country_from_ip(ip)
                        ip_cache[ip] = location

                    # Eğer konum bilgisi alındıysa tüm ilgili kayıtları güncelle
                    if location != "Unknown":
                        update_query = text("""
                        UPDATE attacks
                        SET attackfrom = :location
                        WHERE src_ip = :ip
                        """)
                        result = connection.execute(update_query, {"location": location, "ip": ip})

                        # Güncellenen satır sayısını logla
                        print(f"Güncellenen satır sayısı: {result.rowcount}")

                transaction.commit()  # İşlemi tamamla
            except Exception as e:
                transaction.rollback()  # Hata durumunda geri al
                print(f"Bir hata oluştu: {e}")

        print("attackfrom sütunu başarıyla güncellendi.")

    except Exception as e:
        print(f"Bir hata oluştu: {e}")


if __name__ == "__main__":
    update_attackfrom()
