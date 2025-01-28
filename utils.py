import pycountry
import requests

def get_country_from_ip(ip):
    try:
        # API isteği için URL
        token = "94b092630766c8" 
        url = f"https://ipinfo.io/{ip}?token={token}"
        response = requests.get(url)

        # Yanıt başarılıysa veriyi işle
        if response.status_code == 200:
            data = response.json()
            country_code = data.get("country", "Unknown")  # Ülke kodunu al

            # Ülke kodunu tam ülke adına çevir
            country = pycountry.countries.get(alpha_2=country_code)
            return country.name if country else "Unknown"
        else:
            print(f"API hatası: {response.status_code}")
            return "Unknown"
    except Exception as e:
        print(f"Bir hata oluştu: {e}")
        return "Unknown"
