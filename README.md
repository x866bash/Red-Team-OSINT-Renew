# ScannOSINTkali

ScannOSINTkali adalah tools OSINT (Open Source Intelligence) untuk mengumpulkan informasi dari domain, IP, social media, dan berbagai API publik lainnya. Tools ini menggunakan berbagai sumber seperti WHOIS, Shodan, Twitter, Hunter.io, SecurityTrails, CertSpotter, ZoomEye, Censys, dan AbuseIPDB, Kode ini sebelumnya sangat kacau dan saya berniat untuk di build ulang dengan tambahan sedikit sentuhan `.env` skip jika `API_KEYS` kosong, hasil akan masuk ke dalam file `.json.` dan beberapa fix yang sudah di perbaiki, untuk system menjalankannya sama sekali tidak di rubah, pada dasarnya masih sama namun perubahan itu lah yang membuat saya untuk mengubah sedikit dari kode yang sebelumnya.
Representasi kode dari sahabat ku: 
[![skillfoy](https://avatars.githubusercontent.com/u/20802814?v=4)](https://github.com/skilfoy/Red-Team-OSINT)< />
Terimakasih atas kodenya.
---
````Edditted Code
         ______   ________ ___________.                 .__     
___  ___/  __  \ /  _____//  _____/\_ |__ _____    _____|  |__  
\  \/  />      </   __  \/   __  \  | __ \\__  \  /  ___/  |  \ 
 >    </   --   \  |__\  \  |__\  \ | \_\ \/ __ \_\___ \|   Y  \
/__/\_ \______  /\_____  /\_____  / |___  (____  /____  >___|  /
      \/      \/       \/       \/      \/     \/     \/     \/ 
````
---

## **Fitur Utama**

- WHOIS lookup
- DNS records
- Social Media profiles (LinkedIn, Twitter)
- Shodan scan
- Reverse IP lookup
- Breached account check (Have I Been Pwned)
- Email harvesting (Hunter.io)
- Pastebin mentions
- SecurityTrails data
- PublicWWW search
- CertSpotter certificates
- GitHub repository search
- Wayback Machine snapshots
- ZoomEye information
- Criminal-IP data
- Censys scan
- crt.sh certificate check
- AbuseIPDB reports
- IP validation

## **Fitur Baru**
- .env
- Menjalankan kode tanpa harus mengisi `api_keys`
- hasil di masukan ke dalam file `osint_report_(TARGET).json.json.`

---

## **Prasyarat**

- Python 3.10+  
- API keys untuk beberapa fitur: (Shodan, Twitter, Hunter.io, SecurityTrails, CertSpotter, ZoomEye, Criminal-IP, Censys, AbuseIPDB)

---

## **Instalasi**

1. Clone repository:

```bash
git clone https://github.com/x866bash/ScannOSINTkali.git
cd ScannOSINTkali
```

2. Buat virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt

```

4. Buat file `.env` berdasarkan `.env.example` dan isi API key Anda:

```env
SHODAN_API_KEY=
TWITTER_API_KEY=
TWITTER_API_SECRET_KEY=
TWITTER_ACCESS_TOKEN=
TWITTER_ACCESS_SECRET=
HUNTER_API_KEY=
SECURITYTRAILS_API_KEY=
CERTSPOTTER_API_KEY=
ZOOMEYE_API_KEY=
CRIMINAL_IP_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
ABUSEIPDB_API_KEY=
```

---

## Penggunaannya: 

- Menjalankan
```python
- python osint_script.py
```
- Masukkan domain target ketika diminta, misal:
```yaml
Enter target domain: example.com
```
- Hasil OSINT akan disimpan di file JSON:
```json
osint_report_example.com.json
```

---

Catatan Penting:
 - Pastikan API keys sudah terisi di .env. Jika tidak, beberapa fitur akan dilewati.
 - Tool ini memanfaatkan scraping untuk beberapa sumber (LinkedIn, Pastebin, PublicWWW). Penggunaan yang berlebihan bisa mengakibatkan rate limit.
 - Untuk menghindari error JSON serialization, tool sudah menangani tipe data datetime secara otomatis.

---

## Lisensi
[MIT License](https://github.com/x866bash/Red-Team-OSINT-new_code-/blob/main/LICENSE)

---
<p align="center"><i><b>Made with ❤️  Create by [x866bash]</b></i></p>
---
>>>>>>> 30e8126 (first commit)
