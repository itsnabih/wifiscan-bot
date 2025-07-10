import subprocess
import re
import asyncio
import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from dotenv import load_dotenv

# === LOAD ENV ===
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID"))

# Fungsi untuk menjalankan 'arp -a' dan parsing hasilnya
def get_connected_devices():
    try:
        output = subprocess.check_output("arp -a", shell=True, encoding='utf-8')
        devices = []
        for line in output.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([-\w]+)\s+(\w+)", line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                type_ = match.group(3)
                devices.append((ip, mac, type_))
        return devices
    except Exception as e:
        return str(e)

# Fungsi untuk mendeteksi OS dengan Nmap
def run_nmap(ip):
    try:
        result = subprocess.check_output(f"nmap -O {ip}", shell=True, encoding='utf-8', stderr=subprocess.DEVNULL)
        os = "Tidak diketahui"
        ports = []
        for line in result.splitlines():
            if "Running:" in line:
                os = line.strip()
            elif re.match(r"^\d+/tcp", line):
                ports.append(line.strip())
        return os, ports
    except Exception as e:
        return "Gagal deteksi OS", []

# /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_name = update.effective_user.first_name
    print(f"User {user_name} dengan ID {user_id} memulai bot.")
    await update.message.reply_text(f"Halo, {user_name}! Bot siap digunakan.\nID Telegram kamu: {user_id}")

# /scan_wifi command
async def scan_wifi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Kamu tidak diizinkan menggunakan perintah ini.")
        return

    await update.message.reply_text("🔍 Memindai perangkat di jaringan WiFi... Mohon tunggu sebentar.")
    devices = get_connected_devices()
    if isinstance(devices, str):
        await update.message.reply_text(f"Terjadi kesalahan: {devices}")
        return

    if not devices:
        await update.message.reply_text("Tidak ada perangkat ditemukan.")
        return

    report_lines = []
    for i, (ip, mac, type_) in enumerate(devices, start=1):
        os, ports = run_nmap(ip)
        port_info = "\n      ".join(ports) if ports else "Tidak ada port terbuka"
        report_lines.append(
            f"{i}. IP: {ip}\n"
            f"   MAC: {mac}\n"
            f"   Tipe: {type_}\n"
            f"   OS: {os}\n"
            f"   Port: {port_info}\n"
        )
        await asyncio.sleep(1)  # beri jeda biar tidak terlalu cepat scan

    final_report = "\n".join(report_lines)
    with open("scan_report.txt", "w", encoding="utf-8") as f:
        f.write(final_report)

    await update.message.reply_text("✅ Berikut hasil pemindaian perangkat di jaringan WiFi kamu:")
    await update.message.reply_text(final_report[:4096])  # Telegram limit
    await context.bot.send_document(chat_id=update.effective_chat.id, document=open("scan_report.txt", "rb"))

# Main function
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan_wifi", scan_wifi))

    print("🔧 Bot CSIRT WiFi Scanner berjalan...")
    app.run_polling()

if __name__ == "__main__":
    main()
