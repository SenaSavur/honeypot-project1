from sqlalchemy import create_engine
from dotenv import load_dotenv
import os

# Veritabanı bağlantısı
def get_database_connection():
    try:
        load_dotenv("config.env")
        db_url = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
        engine = create_engine(db_url)
        return engine
    except Exception as e:
        print(f"Veritabanı bağlantı hatası: {e}")
        return None
    
if __name__ == "__main__":
    engine = get_database_connection()
    if engine:
        print("Veritabanı bağlantısı başarılı!")
    else:
        print("Veritabanı bağlantısı başarısız.")

