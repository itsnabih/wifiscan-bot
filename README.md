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
