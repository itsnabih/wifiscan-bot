#!/usr/bin/env python3
import subprocess
import re
import asyncio
import os
import platform
import socket
import logging
import getpass
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from dotenv import load_dotenv
from datetime import datetime

# === SETUP LOGGING ===
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# === LOAD ENV ===
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID"))

# === SUDO PASSWORD MANAGEMENT ===
SUDO_PASSWORD = None

def get_sudo_password():
    """Mendapatkan password sudo dari user"""
    global SUDO_PASSWORD
    if SUDO_PASSWORD is None:
        try:
            # Cek apakah user bisa sudo tanpa password
            result = subprocess.run(['sudo', '-n', 'echo', 'test'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("Sudo tersedia tanpa password")
                SUDO_PASSWORD = ""
                return SUDO_PASSWORD
            else:
                # Minta password dari user
                print("\n🔐 Bot memerlukan akses sudo untuk beberapa fitur scanning.")
                print("💡 Password hanya akan diminta sekali dan disimpan di memory.")
                SUDO_PASSWORD = getpass.getpass("🔑 Masukkan password sudo: ")
                
                # Test password
                test_cmd = f"echo '{SUDO_PASSWORD}' | sudo -S echo 'password test'"
                test_result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
                if test_result.returncode != 0:
                    logger.error("Password sudo tidak valid!")
                    SUDO_PASSWORD = None
                    return None
                else:
                    logger.info("Password sudo berhasil diverifikasi")
                    return SUDO_PASSWORD
        except Exception as e:
            logger.error(f"Error getting sudo password: {e}")
            return None
    return SUDO_PASSWORD

def run_sudo_command(command, timeout=30):
    """Menjalankan command dengan sudo"""
    global SUDO_PASSWORD
    
    try:
        # Coba tanpa password dulu
        result = subprocess.run(['sudo', '-n'] + command.split(), 
                              capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return result
        
        # Jika gagal, gunakan password
        if SUDO_PASSWORD is None:
            SUDO_PASSWORD = get_sudo_password()
            if SUDO_PASSWORD is None:
                return None
        
        # Jalankan dengan password
        if SUDO_PASSWORD == "":
            # Sudo tanpa password
            result = subprocess.run(['sudo'] + command.split(), 
                                  capture_output=True, text=True, timeout=timeout)
        else:
            # Sudo dengan password
            full_command = f"echo '{SUDO_PASSWORD}' | sudo -S {command}"
            result = subprocess.run(full_command, shell=True, 
                                  capture_output=True, text=True, timeout=timeout)
        
        return result
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout executing sudo command: {command}")
        return None
    except Exception as e:
        logger.error(f"Error executing sudo command: {e}")
        return None

# === DEPENDENCY CHECKER ===
def check_dependencies():
    """Memeriksa apakah tools yang diperlukan sudah terinstall"""
    dependencies = {
        'nmap': 'sudo apt-get install nmap',
        'arp-scan': 'sudo apt-get install arp-scan',
        'net-tools': 'sudo apt-get install net-tools',
        'arp': 'sudo apt-get install net-tools'
    }
    
    missing = []
    for tool, install_cmd in dependencies.items():
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            missing.append(f"{tool} - Install dengan: {install_cmd}")
    
    if missing:
        logger.warning(f"Dependencies yang hilang: {', '.join([m.split(' -')[0] for m in missing])}")
    return missing

# === NETWORK DISCOVERY ===
def get_network_interface():
    """Mendapatkan network interface yang aktif"""
    try:
        # Coba dapatkan interface dari default route
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            match = re.search(r'dev\s+(\w+)', result.stdout)
            if match:
                return match.group(1)
        
        # Fallback ke interface yang umum
        common_interfaces = ['wlan0', 'eth0', 'enp0s3', 'wlp2s0']
        for interface in common_interfaces:
            if os.path.exists(f'/sys/class/net/{interface}'):
                return interface
        
        return 'eth0'  # Default fallback
    except Exception as e:
        logger.error(f"Error getting network interface: {e}")
        return 'eth0'

def get_network_range():
    """Mendapatkan network range dari interface aktif"""
    try:
        interface = get_network_interface()
        result = subprocess.run(['ip', 'addr', 'show', interface], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            # Cari IP dan subnet mask
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
            if match:
                return match.group(1)
        
        # Fallback ke range umum
        return "192.168.1.0/24"
    except Exception as e:
        logger.error(f"Error getting network range: {e}")
        return "192.168.1.0/24"

# === TEXT SANITIZATION ===
def escape_markdown_v2(text):
    """Escape special characters for Telegram MarkdownV2"""
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return ''.join(f'\\{char}' if char in escape_chars else char for char in text)

def sanitize_text(text):
    """Sanitize text untuk menghindari parsing errors"""
    if not text:
        return "Unknown"
    
    # Remove atau escape karakter yang bermasalah
    text = str(text).replace('`', "'").replace('*', '-').replace('_', '-')
    text = re.sub(r'[^\w\s\-\.\:\(\)\[\]/]', '', text)
    return text[:100]  # Batasi panjang

# === DEVICE DISCOVERY ===
def get_connected_devices_arp():
    """Menggunakan arp -a dengan sudo untuk mendapatkan perangkat yang terhubung"""
    try:
        logger.info("Menjalankan arp -a dengan sudo...")
        
        # Coba dengan sudo
        result = run_sudo_command("arp -a")
        
        if result is None or result.returncode != 0:
            logger.warning("Gagal menjalankan sudo arp -a, mencoba tanpa sudo...")
            # Fallback tanpa sudo
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("arp command gagal dijalankan")
                return []
        
        output = result.stdout
        devices = []
        
        for line in output.splitlines():
            # Pattern untuk parsing output arp -a (format bisa berbeda)
            # Format 1: gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0
            match1 = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\w:]+)', line)
            # Format 2: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on wlan0
            match2 = re.search(r'\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\w:]+)', line)
            # Format 3: 192.168.1.1 ether aa:bb:cc:dd:ee:ff C wlan0
            match3 = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([\w:]+)', line)
            
            if match1:
                ip = match1.group(1)
                mac = match1.group(2)
                devices.append((ip, mac, "arp"))
            elif match2:
                ip = match2.group(1)
                mac = match2.group(2)
                devices.append((ip, mac, "arp"))
            elif match3:
                ip = match3.group(1)
                mac = match3.group(2)
                devices.append((ip, mac, "arp"))
        
        logger.info(f"Ditemukan {len(devices)} devices via arp")
        return devices
    except Exception as e:
        logger.error(f"Error with arp -a: {e}")
        return []

def ping_sweep():
    """Melakukan ping sweep untuk menemukan perangkat aktif"""
    try:
        network_range = get_network_range()
        # Extract network base (e.g., 192.168.1 from 192.168.1.0/24)
        network_base = '.'.join(network_range.split('.')[:-1])
        
        devices = []
        logger.info(f"Melakukan ping sweep pada {network_base}.1-254")
        
        # Ping range 1-254
        for i in range(1, 255):
            ip = f"{network_base}.{i}"
            try:
                # Ping dengan timeout 1 detik
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    devices.append((ip, "unknown", "ping"))
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
        
        logger.info(f"Ditemukan {len(devices)} devices via ping sweep")
        return devices
    except Exception as e:
        logger.error(f"Error with ping sweep: {e}")
        return []

def get_connected_devices_arp_scan():
    """Menggunakan arp-scan dengan sudo untuk scan yang lebih akurat"""
    try:
        network_range = get_network_range()
        interface = get_network_interface()
        
        logger.info(f"Menjalankan arp-scan pada {network_range} interface {interface}")
        
        # Gunakan sudo untuk arp-scan
        command = f"arp-scan --interface={interface} {network_range}"
        result = run_sudo_command(command)
        
        if result is None or result.returncode != 0:
            logger.warning("Gagal menjalankan sudo arp-scan")
            return []
        
        output = result.stdout
        devices = []
        
        for line in output.splitlines():
            # Pattern untuk parsing output arp-scan
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([\w:]+)\s+(.+)', line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                vendor = match.group(3).strip()
                devices.append((ip, mac, vendor))
        
        logger.info(f"Ditemukan {len(devices)} devices via arp-scan")
        return devices
    except Exception as e:
        logger.error(f"Error with arp-scan: {e}")
        return []

def get_connected_devices():
    """Gabungan dari berbagai metode untuk mendapatkan devices"""
    devices = []
    
    # Method 1: Coba dengan arp-scan terlebih dahulu (lebih akurat)
    if subprocess.run(['which', 'arp-scan'], capture_output=True).returncode == 0:
        logger.info("Menggunakan arp-scan untuk device discovery...")
        arp_scan_devices = get_connected_devices_arp_scan()
        if arp_scan_devices:
            devices.extend(arp_scan_devices)
    
    # Method 2: Fallback ke arp -a
    if not devices:
        logger.info("Menggunakan arp -a untuk device discovery...")
        arp_devices = get_connected_devices_arp()
        devices.extend(arp_devices)
    
    # Method 3: Jika masih kosong, lakukan ping sweep
    if not devices:
        logger.info("Menggunakan ping sweep untuk device discovery...")
        ping_devices = ping_sweep()
        devices.extend(ping_devices)
    
    # Method 4: Cek /proc/net/arp sebagai alternatif
    if not devices:
        logger.info("Menggunakan /proc/net/arp untuk device discovery...")
        proc_devices = get_devices_from_proc()
        devices.extend(proc_devices)
    
    # Hapus duplikat berdasarkan IP
    unique_devices = []
    seen_ips = set()
    for device in devices:
        ip = device[0]
        if ip not in seen_ips:
            unique_devices.append(device)
            seen_ips.add(ip)
    
    logger.info(f"Total unique devices found: {len(unique_devices)}")
    return unique_devices

def get_devices_from_proc():
    """Membaca /proc/net/arp sebagai alternatif"""
    try:
        with open('/proc/net/arp', 'r') as f:
            lines = f.readlines()
        
        devices = []
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[0]
                mac = parts[3]
                if ip != "0.0.0.0" and mac != "00:00:00:00:00:00":
                    devices.append((ip, mac, "proc"))
        
        logger.info(f"Ditemukan {len(devices)} devices via /proc/net/arp")
        return devices
    except Exception as e:
        logger.error(f"Error reading /proc/net/arp: {e}")
        return []

# === OS DETECTION ===
def run_nmap_os_detection(ip):
    """Mendeteksi OS dengan Nmap menggunakan sudo"""
    try:
        logger.info(f"Menjalankan nmap OS detection untuk {ip}")
        
        # Nmap dengan OS detection dan service detection menggunakan sudo
        command = f"nmap -O -sS -sV --top-ports 100 {ip}"
        result = run_sudo_command(command, timeout=60)
        
        if result is None or result.returncode != 0:
            logger.warning(f"Sudo nmap gagal untuk {ip}, mencoba tanpa sudo...")
            # Fallback tanpa sudo
            command = f"nmap -sS -sV --top-ports 50 {ip}"
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  text=True, timeout=30)
        
        if result.returncode != 0:
            logger.warning(f"Nmap gagal untuk {ip}, menggunakan basic scan...")
            return "Gagal deteksi OS", [], []
        
        os_info = "Tidak diketahui"
        ports = []
        services = []
        
        for line in result.stdout.splitlines():
            if "Running:" in line or "OS details:" in line:
                os_info = sanitize_text(line.strip())
            elif re.match(r'^\d+/tcp', line):
                ports.append(sanitize_text(line.strip()))
            elif "Service Info:" in line:
                services.append(sanitize_text(line.strip()))
        
        return os_info, ports, services
    except Exception as e:
        logger.error(f"Error with nmap OS detection for {ip}: {e}")
        return "Gagal deteksi OS", [], []

def basic_port_scan(ip):
    """Scan port dasar tanpa nmap"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080]
    open_ports = []
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(f"{port}/tcp open")
            sock.close()
        except:
            pass
    
    return open_ports

# === BOT COMMANDS ===
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command /start"""
    user_id = update.effective_user.id
    user_name = update.effective_user.first_name
    
    logger.info(f"User {user_name} dengan ID {user_id} memulai bot.")
    
    # Cek status sudo
    sudo_status = "❌ Tidak tersedia"
    if SUDO_PASSWORD is not None:
        sudo_status = "✅ Tersedia"
    elif subprocess.run(['sudo', '-n', 'echo', 'test'], capture_output=True).returncode == 0:
        sudo_status = "✅ Tersedia (tanpa password)"
    
    system_info = f"""🤖 WiFi Scanner Bot untuk Debian Linux

👤 Halo, {user_name}!
🆔 ID Telegram: {user_id}
🖥️ System: {platform.system()} {platform.release()}
🌐 Network Interface: {get_network_interface()}
📡 Network Range: {get_network_range()}
🔐 Sudo Access: {sudo_status}

Commands:
/start - Mulai bot
/scan_wifi - Scan perangkat di jaringan
/check_deps - Cek dependencies
/system_info - Info sistem
/sudo_test - Test sudo access

⚠️ Catatan: Bot memerlukan sudo access untuk fitur advanced scanning."""
    
    await update.message.reply_text(system_info)

async def sudo_test(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command /sudo_test"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Kamu tidak diizinkan menggunakan perintah ini.")
        return
    
    await update.message.reply_text("🔍 Testing sudo access...")
    
    try:
        # Test sudo access
        result = run_sudo_command("echo 'Sudo test successful'")
        
        if result and result.returncode == 0:
            await update.message.reply_text("✅ Sudo access berhasil!\n" + result.stdout)
        else:
            await update.message.reply_text("❌ Sudo access gagal. Pastikan password sudo sudah diatur.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error testing sudo: {e}")

async def check_deps(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command /check_deps"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Kamu tidak diizinkan menggunakan perintah ini.")
        return
    
    await update.message.reply_text("🔍 Memeriksa dependencies...")
    
    missing = check_dependencies()
    
    if not missing:
        await update.message.reply_text("✅ Semua dependencies sudah terinstall!")
    else:
        deps_info = "❌ Dependencies yang hilang:\n\n"
        for dep in missing:
            deps_info += f"• {dep}\n"
        
        await update.message.reply_text(deps_info)

async def system_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command /system_info"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Kamu tidak diizinkan menggunakan perintah ini.")
        return
    
    try:
        # Cek status sudo
        sudo_status = "❌ Tidak tersedia"
        if SUDO_PASSWORD is not None:
            sudo_status = "✅ Tersedia"
        elif subprocess.run(['sudo', '-n', 'echo', 'test'], capture_output=True).returncode == 0:
            sudo_status = "✅ Tersedia (tanpa password)"
        
        # Informasi sistem
        info = f"""📋 System Information

🖥️ System: {platform.system()} {platform.release()}
🔧 Architecture: {platform.machine()}
🌐 Hostname: {socket.gethostname()}
📡 Network Interface: {get_network_interface()}
🌍 Network Range: {get_network_range()}
🔐 Sudo Access: {sudo_status}
⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔧 Dependencies Status:"""
        
        missing = check_dependencies()
        if not missing:
            info += "\n✅ All dependencies installed"
        else:
            info += "\n❌ Missing dependencies found"
        
        await update.message.reply_text(info)
    except Exception as e:
        await update.message.reply_text(f"❌ Error getting system info: {e}")

async def scan_wifi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Command /scan_wifi"""
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("❌ Kamu tidak diizinkan menggunakan perintah ini.")
        return
    
    await update.message.reply_text("🔍 Memindai perangkat di jaringan WiFi... Mohon tunggu sebentar.")
    
    try:
        # Cek dependencies terlebih dahulu
        missing = check_dependencies()
        if missing:
            warning_msg = "⚠️ Peringatan: Beberapa dependencies hilang:\n"
            for dep in missing[:3]:  # Batasi hanya 3 dependencies
                warning_msg += f"• {dep.split(' -')[0]}\n"
            await update.message.reply_text(warning_msg)
        
        # Cek sudo access
        if SUDO_PASSWORD is None:
            test_result = run_sudo_command("echo 'test'")
            if test_result is None or test_result.returncode != 0:
                await update.message.reply_text("⚠️ Sudo access tidak tersedia. Beberapa fitur mungkin tidak optimal.")
        
        devices = get_connected_devices()
        
        if not devices:
            await update.message.reply_text("❌ Tidak ada perangkat ditemukan.")
            return
        
        # Buat laporan yang lebih sederhana untuk menghindari parsing errors
        report_lines = []
        report_lines.append("📊 Network Scan Report")
        report_lines.append(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"🌐 Network: {get_network_range()}")
        report_lines.append(f"📡 Interface: {get_network_interface()}")
        report_lines.append(f"🔢 Total Devices: {len(devices)}")
        report_lines.append(f"🔐 Sudo Status: {'✅ Active' if SUDO_PASSWORD is not None else '❌ Not Available'}")
        report_lines.append("")
        report_lines.append("📱 Device Details:")
        report_lines.append("=" * 50)
        
        for i, device in enumerate(devices, start=1):
            ip = sanitize_text(device[0])
            mac = sanitize_text(device[1])
            type_or_vendor = sanitize_text(device[2] if len(device) > 2 else "Unknown")
            
            # Kirim progress update
            progress_msg = f"🔍 Scanning device {i}/{len(devices)}: {ip}"
            await update.message.reply_text(progress_msg)
            
            # OS Detection dengan timeout yang lebih pendek
            try:
                os_info, ports, services = run_nmap_os_detection(ip)
                
                # Jika nmap gagal, gunakan basic port scan
                if not ports:
                    ports = basic_port_scan(ip)
                
                port_info = ", ".join(ports[:3]) if ports else "No open ports found"  # Batasi ke 3 ports
                
                device_report = f"""
🔹 Device {i}:
   📍 IP: {ip}
   🔧 MAC: {mac}
   🏷️ Type/Vendor: {type_or_vendor}
   💻 OS: {sanitize_text(os_info)}
   🚪 Ports: {port_info}
"""
                
                report_lines.append(device_report)
                
            except Exception as e:
                logger.error(f"Error scanning device {ip}: {e}")
                device_report = f"""
🔹 Device {i}:
   📍 IP: {ip}
   🔧 MAC: {mac}
   🏷️ Type/Vendor: {type_or_vendor}
   💻 OS: Scan failed
   🚪 Ports: Scan failed
"""
                report_lines.append(device_report)
            
            # Berikan jeda untuk menghindari spam
            await asyncio.sleep(1)
        
        # Gabungkan semua hasil
        final_report = "\n".join(report_lines)
        
        # Simpan ke file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"wifi_scan_report_{timestamp}.txt"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(final_report)
        
        # Kirim hasil (split jika terlalu panjang)
        max_length = 3500  # Lebih konservatif
        if len(final_report) > max_length:
            # Split menjadi beberapa pesan
            chunks = []
            current_chunk = ""
            
            for line in report_lines:
                if len(current_chunk + line + "\n") > max_length:
                    if current_chunk:
                        chunks.append(current_chunk)
                    current_chunk = line + "\n"
                else:
                    current_chunk += line + "\n"
            
            if current_chunk:
                chunks.append(current_chunk)
            
            for i, chunk in enumerate(chunks, 1):
                await update.message.reply_text(f"📄 Report part {i}/{len(chunks)}:\n\n{chunk}")
        else:
            await update.message.reply_text(final_report)
        
        # Kirim file
        try:
            await context.bot.send_document(
                chat_id=update.effective_chat.id, 
                document=open(filename, "rb"),
                caption=f"📄 Complete scan report - {len(devices)} devices found"
            )
        except Exception as e:
            logger.error(f"Error sending document: {e}")
        
        # Hapus file setelah dikirim
        try:
            os.remove(filename)
        except:
            pass
        
    except Exception as e:
        logger.error(f"Error in scan_wifi: {e}")
        await update.message.reply_text(f"❌ Terjadi kesalahan saat scanning: {str(e)[:200]}")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Error handler untuk menangani error"""
    logger.error(f"Exception while handling an update: {context.error}")
    
    # Kirim pesan error ke user jika memungkinkan
    if update and update.effective_chat:
        try:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="❌ Terjadi error. Silakan coba lagi atau hubungi admin."
            )
        except:
            pass

# === MAIN FUNCTION ===
def main():
    """Main function"""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN tidak ditemukan! Pastikan file .env sudah dikonfigurasi.")
        return
    
    if not ADMIN_ID:
        logger.error("ADMIN_ID tidak ditemukan! Pastikan file .env sudah dikonfigurasi.")
        return
    
    # Cek dependencies
    missing = check_dependencies()
    if missing:
        logger.warning("Beberapa dependencies hilang, beberapa fitur mungkin tidak berfungsi optimal.")
    
    # Setup sudo access
    print("🔧 Memeriksa sudo access...")
    sudo_password = get_sudo_password()
    if sudo_password is not None:
        print("✅ Sudo access berhasil dikonfigurasi")
    else:
        print("⚠️ Sudo access tidak tersedia, beberapa fitur akan terbatas")
    # Build
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    #handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan_wifi", scan_wifi))
    app.add_handler(CommandHandler("check_deps", check_deps))
    app.add_handler(CommandHandler("system_info", system_info))
    app.add_handler(CommandHandler("sudo_test", sudo_test))
    
    #error handler
    app.add_error_handler(error_handler)
    
    logger.info("🚀 Bot WiFi Scanner untuk Debian Linux berjalan...")
    logger.info(f"👤 Admin ID: {ADMIN_ID}")
    logger.info(f"🔐 Sudo Status: {'✅ Available' if sudo_password is not None else '❌ Not Available'}")
    
    app.run_polling()

if __name__ == "__main__":
    main()