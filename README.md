Sip, Nabih! Dengan nama proyek dan repo **`wifiscan-bot`**, berikut adalah versi final dan rapi dari file **`README.md`** yang siap kamu gunakan langsung di GitHub.

---

### 📄 `README.md` untuk `wifiscan-bot`

````markdown
# 🛡️ wifiscan-bot – CSIRT WiFi Scanner Bot 🤖

Bot Telegram pribadi untuk memindai perangkat yang terhubung ke jaringan WiFi rumah atau kantor kamu. Cocok digunakan oleh tim CSIRT, praktisi keamanan jaringan, maupun pengguna rumahan yang ingin tahu siapa saja yang terhubung ke jaringan mereka.

> Dibuat dengan Python + Telegram Bot API + Nmap (kompatibel untuk Windows)

---

## ✨ Fitur Utama

- 🔍 `/scan_wifi`  
  Deteksi perangkat aktif di jaringan WiFi kamu secara real-time  
  Info lengkap: IP address, MAC address, tipe koneksi, OS deteksi (via Nmap), dan port terbuka  
  Output dikirim dalam bentuk teks + file `scan_report.txt`

- 👋 `/start`  
  Menyambut pengguna dan menampilkan ID Telegram mereka  
  Digunakan untuk otentikasi admin bot

---

## 📦 Teknologi

| Komponen                | Fungsi                            |
|-------------------------|-----------------------------------|
| Python 3.10+            | Bahasa pemrograman utama          |
| `python-telegram-bot`   | Library Telegram Bot async        |
| `nmap` (Windows CLI)    | Deteksi OS + port scanning        |
| `arp -a` (Windows CLI)  | Deteksi perangkat di jaringan LAN |
| `dotenv`                | Keamanan token via file `.env`    |

---

## 🚀 Instalasi & Setup

### 1. Clone Repo

```bash
git clone https://github.com/namamu/wifiscan-bot.git
cd wifiscan-bot
````

### 2. Install Dependency Python

```bash
pip install -r requirements.txt
```

### 3. Install Nmap

* Unduh dari: [https://nmap.org/download.html](https://nmap.org/download.html)
* Jalankan `.exe` dan centang opsi "Add to PATH"

### 4. Buat File `.env`

Buat file `.env` di direktori utama:

```
BOT_TOKEN=isi_token_bot_kamu
ADMIN_ID=123456789
```

### 5. Jalankan Bot

> ⚠️ Harus dijalankan sebagai **Administrator** agar `arp` dan `nmap` berjalan lancar.

```bash
python clayynh_bot.py
```

---

## 📁 Contoh Output

```text
1. IP: 192.168.1.10
   MAC: 48:2C:A0:XX:XX:XX
   Tipe: dynamic
   OS: Running: Linux 5.X (Ubuntu)
   Port:
      22/tcp open ssh
      80/tcp open http
```

---

## 🛡️ Keamanan

* Token dan ID Telegram admin disimpan di `.env` (tidak ikut di-push berkat `.gitignore`)
* Bot hanya merespon perintah sensitif jika dikirim oleh admin ID yang sah
* Tidak menyimpan informasi pengguna secara permanen

---

## 📌 File Penting

* `clayynh_bot.py`: Source code utama bot
* `.env`: Variabel rahasia (tidak dikomit)
* `requirements.txt`: Dependensi Python
* `.gitignore`: Proteksi terhadap file sensitif seperti `.env` dan `scan_report.txt`

