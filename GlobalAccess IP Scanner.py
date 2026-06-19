import sys
import json
import csv
import socket
import struct
import time
import threading
import subprocess
import platform
import ipaddress
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import urllib.request
import urllib.error
import ssl

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QLabel, QProgressBar, QComboBox, QCheckBox, QSpinBox, QTabWidget,
    QFileDialog, QMessageBox, QSplitter, QFrame, QHeaderView,
    QStatusBar, QToolBar, QGroupBox, QGridLayout, QScrollArea
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QSettings
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QIcon, QAction, QPixmap
)

TRANSLATIONS = {
    'en': {
        'title': 'IP Range Scanner & Connectivity Analyzer',
        'ip_ranges': 'IP Ranges / CIDR',
        'ip_placeholder': 'Enter IP ranges (e.g., 192.168.1.0/24, 10.0.0.1-10.0.0.100)',
        'threads': 'Threads',
        'timeout': 'Timeout (s)',
        'start_scan': 'Start Scan',
        'stop_scan': 'Stop Scan',
        'export_json': 'Export JSON',
        'export_csv': 'Export CSV',
        'clear': 'Clear',
        'results': 'Results',
        'log': 'Log',
        'summary': 'Summary',
        'ip': 'IP Address',
        'ping': 'Ping',
        'latency': 'Latency (ms)',
        'jitter': 'Jitter (ms)',
        'packet_loss': 'Packet Loss %',
        'port_80': 'Port 80',
        'port_443': 'Port 443',
        'tls': 'TLS',
        'https': 'HTTPS',
        'speed': 'Speed (KB/s)',
        'traceroute': 'Hops',
        'status': 'Status',
        'filter': 'Filter',
        'sort_by': 'Sort By',
        'theme': 'Theme',
        'language': 'Language',
        'healthy': 'Healthy IPs',
        'total': 'Total Scanned',
        'scanning': 'Scanning...',
        'done': 'Scan Complete',
        'blocked': 'BLOCKED',
        'open': 'OPEN',
        'closed': 'CLOSED',
        'reachable': 'REACHABLE',
        'unreachable': 'UNREACHABLE',
        'success': 'SUCCESS',
        'failed': 'FAILED',
        'dpi_detected': 'DPI/Filter Detected',
        'settings': 'Settings',
        'ping_test': 'ICMP Ping',
        'tcp_test': 'TCP Test',
        'https_test': 'HTTPS Test',
        'traceroute_test': 'Traceroute',
        'all_tests': 'All Tests',
        'progress': 'Progress',
        'elapsed': 'Elapsed',
        'remaining': 'Remaining',
        'pause': 'Pause',
        'resume': 'Resume',
    },
    'fa': {
        'title': 'اسکنر رنج IP و تحلیلگر اتصال',
        'ip_ranges': 'رنج‌های IP / CIDR',
        'ip_placeholder': 'رنج IP وارد کنید (مثال: 192.168.1.0/24)',
        'threads': 'تعداد Thread',
        'timeout': 'Timeout (ثانیه)',
        'start_scan': 'شروع اسکن',
        'stop_scan': 'توقف اسکن',
        'export_json': 'خروجی JSON',
        'export_csv': 'خروجی CSV',
        'clear': 'پاک کردن',
        'results': 'نتایج',
        'log': 'گزارش',
        'summary': 'خلاصه',
        'ip': 'آدرس IP',
        'ping': 'پینگ',
        'latency': 'تأخیر (ms)',
        'jitter': 'جیتر (ms)',
        'packet_loss': 'افت بسته %',
        'port_80': 'پورت 80',
        'port_443': 'پورت 443',
        'tls': 'TLS',
        'https': 'HTTPS',
        'speed': 'سرعت (KB/s)',
        'traceroute': 'هاپ‌ها',
        'status': 'وضعیت',
        'filter': 'فیلتر',
        'sort_by': 'مرتب‌سازی',
        'theme': 'تم',
        'language': 'زبان',
        'healthy': 'IP سالم',
        'total': 'کل اسکن شده',
        'scanning': 'در حال اسکن...',
        'done': 'اسکن کامل شد',
        'blocked': 'مسدود',
        'open': 'باز',
        'closed': 'بسته',
        'reachable': 'قابل دسترس',
        'unreachable': 'غیرقابل دسترس',
        'success': 'موفق',
        'failed': 'ناموفق',
        'dpi_detected': 'DPI/فیلتر شناسایی شد',
        'settings': 'تنظیمات',
        'ping_test': 'پینگ ICMP',
        'tcp_test': 'تست TCP',
        'https_test': 'تست HTTPS',
        'traceroute_test': 'مسیریابی',
        'all_tests': 'همه تست‌ها',
        'progress': 'پیشرفت',
        'elapsed': 'گذشته',
        'remaining': 'باقیمانده',
        'pause': 'مکث',
        'resume': 'ادامه',
    },
    'zh': {
        'title': 'IP范围扫描器和连接分析器',
        'ip_ranges': 'IP范围 / CIDR',
        'ip_placeholder': '输入IP范围 (例如: 192.168.1.0/24)',
        'threads': '线程数',
        'timeout': '超时 (秒)',
        'start_scan': '开始扫描',
        'stop_scan': '停止扫描',
        'export_json': '导出JSON',
        'export_csv': '导出CSV',
        'clear': '清除',
        'results': '结果',
        'log': '日志',
        'summary': '摘要',
        'ip': 'IP地址',
        'ping': 'Ping',
        'latency': '延迟 (ms)',
        'jitter': '抖动 (ms)',
        'packet_loss': '丢包率 %',
        'port_80': '端口 80',
        'port_443': '端口 443',
        'tls': 'TLS',
        'https': 'HTTPS',
        'speed': '速度 (KB/s)',
        'traceroute': '跳数',
        'status': '状态',
        'filter': '过滤',
        'sort_by': '排序',
        'theme': '主题',
        'language': '语言',
        'healthy': '健康IP',
        'total': '总扫描数',
        'scanning': '扫描中...',
        'done': '扫描完成',
        'blocked': '已封锁',
        'open': '开放',
        'closed': '关闭',
        'reachable': '可达',
        'unreachable': '不可达',
        'success': '成功',
        'failed': '失败',
        'dpi_detected': '检测到DPI/过滤',
        'settings': '设置',
        'ping_test': 'ICMP Ping',
        'tcp_test': 'TCP测试',
        'https_test': 'HTTPS测试',
        'traceroute_test': '路由追踪',
        'all_tests': '所有测试',
        'progress': '进度',
        'elapsed': '已用时',
        'remaining': '剩余',
        'pause': '暂停',
        'resume': '继续',
    }
}

DARK_THEME = """
QMainWindow, QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Segoe UI', Arial, sans-serif;
}
QTabWidget::pane {
    border: 1px solid #16213e;
    background-color: #16213e;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #0f3460;
    color: #a0a0b0;
    padding: 8px 16px;
    border-radius: 4px 4px 0 0;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #e94560;
    color: white;
}
QTabBar::tab:hover {
    background-color: #533483;
}
QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: 1px solid #533483;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: bold;
    min-height: 32px;
}
QPushButton:hover {
    background-color: #533483;
    border-color: #e94560;
}
QPushButton:pressed {
    background-color: #e94560;
}
QPushButton:disabled {
    background-color: #2a2a3e;
    color: #606070;
    border-color: #404050;
}
QPushButton#startBtn {
    background-color: #1a6b3c;
    border-color: #2ecc71;
    color: white;
}
QPushButton#startBtn:hover {
    background-color: #2ecc71;
    color: #1a1a2e;
}
QPushButton#stopBtn {
    background-color: #6b1a1a;
    border-color: #e74c3c;
    color: white;
}
QPushButton#stopBtn:hover {
    background-color: #e74c3c;
    color: white;
}
QLineEdit, QTextEdit, QSpinBox, QComboBox {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px;
    selection-background-color: #533483;
}
QLineEdit:focus, QTextEdit:focus {
    border-color: #e94560;
}
QTableWidget {
    background-color: #16213e;
    color: #e0e0e0;
    gridline-color: #0f3460;
    border: 1px solid #0f3460;
    border-radius: 4px;
    alternate-background-color: #1a2040;
}
QTableWidget::item {
    padding: 6px;
    border-bottom: 1px solid #0f3460;
}
QTableWidget::item:selected {
    background-color: #533483;
    color: white;
}
QHeaderView::section {
    background-color: #0f3460;
    color: #e0e0e0;
    padding: 8px;
    border: none;
    border-right: 1px solid #533483;
    font-weight: bold;
}
QProgressBar {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    text-align: center;
    color: white;
    height: 20px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #533483, stop:1 #e94560);
    border-radius: 3px;
}
QGroupBox {
    border: 1px solid #0f3460;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 8px;
    color: #a0a0c0;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #e94560;
}
QScrollBar:vertical {
    background: #16213e;
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #533483;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #e94560;
}
QLabel {
    color: #c0c0d0;
}
QStatusBar {
    background-color: #0f3460;
    color: #a0a0b0;
    border-top: 1px solid #533483;
}
QToolBar {
    background-color: #0f3460;
    border-bottom: 1px solid #533483;
    spacing: 4px;
    padding: 4px;
}
QCheckBox {
    color: #c0c0d0;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #533483;
    border-radius: 3px;
    background-color: #16213e;
}
QCheckBox::indicator:checked {
    background-color: #e94560;
    border-color: #e94560;
}
QSplitter::handle {
    background-color: #0f3460;
    width: 3px;
}
"""

LIGHT_THEME = """
QMainWindow, QWidget {
    background-color: #f5f7fa;
    color: #2c3e50;
    font-family: 'Segoe UI', Arial, sans-serif;
}
QTabWidget::pane {
    border: 1px solid #dce1e7;
    background-color: #ffffff;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #e8ecf0;
    color: #5a6a7a;
    padding: 8px 16px;
    border-radius: 4px 4px 0 0;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #3498db;
    color: white;
}
QTabBar::tab:hover {
    background-color: #bdc3c7;
}
QPushButton {
    background-color: #ecf0f1;
    color: #2c3e50;
    border: 1px solid #bdc3c7;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: bold;
    min-height: 32px;
}
QPushButton:hover {
    background-color: #3498db;
    color: white;
    border-color: #2980b9;
}
QPushButton:pressed {
    background-color: #2980b9;
    color: white;
}
QPushButton:disabled {
    background-color: #ecf0f1;
    color: #bdc3c7;
}
QPushButton#startBtn {
    background-color: #27ae60;
    border-color: #2ecc71;
    color: white;
}
QPushButton#startBtn:hover {
    background-color: #2ecc71;
}
QPushButton#stopBtn {
    background-color: #e74c3c;
    border-color: #c0392b;
    color: white;
}
QPushButton#stopBtn:hover {
    background-color: #c0392b;
}
QLineEdit, QTextEdit, QSpinBox, QComboBox {
    background-color: #ffffff;
    color: #2c3e50;
    border: 1px solid #bdc3c7;
    border-radius: 4px;
    padding: 6px;
    selection-background-color: #3498db;
}
QLineEdit:focus, QTextEdit:focus {
    border-color: #3498db;
}
QTableWidget {
    background-color: #ffffff;
    color: #2c3e50;
    gridline-color: #dce1e7;
    border: 1px solid #dce1e7;
    border-radius: 4px;
    alternate-background-color: #f8f9fa;
}
QTableWidget::item {
    padding: 6px;
    border-bottom: 1px solid #ecf0f1;
}
QTableWidget::item:selected {
    background-color: #3498db;
    color: white;
}
QHeaderView::section {
    background-color: #ecf0f1;
    color: #2c3e50;
    padding: 8px;
    border: none;
    border-right: 1px solid #bdc3c7;
    font-weight: bold;
}
QProgressBar {
    background-color: #ecf0f1;
    border: 1px solid #bdc3c7;
    border-radius: 4px;
    text-align: center;
    color: #2c3e50;
    height: 20px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #3498db, stop:1 #2ecc71);
    border-radius: 3px;
}
QGroupBox {
    border: 1px solid #dce1e7;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 8px;
    color: #5a6a7a;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #3498db;
}
QScrollBar:vertical {
    background: #ecf0f1;
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #bdc3c7;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #3498db;
}
QLabel {
    color: #5a6a7a;
}
QStatusBar {
    background-color: #ecf0f1;
    color: #5a6a7a;
    border-top: 1px solid #bdc3c7;
}
QToolBar {
    background-color: #ecf0f1;
    border-bottom: 1px solid #bdc3c7;
    spacing: 4px;
    padding: 4px;
}
QCheckBox {
    color: #5a6a7a;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #bdc3c7;
    border-radius: 3px;
    background-color: #ffffff;
}
QCheckBox::indicator:checked {
    background-color: #3498db;
    border-color: #2980b9;
}
QSplitter::handle {
    background-color: #dce1e7;
    width: 3px;
}
"""


def ping_host(host: str, timeout: int = 2, count: int = 4) -> dict:
    result = {'reachable': False, 'latency': None, 'jitter': None, 'packet_loss': 100.0}
    try:
        system = platform.system().lower()
        if system == 'windows':
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
        else:
            cmd = ['ping', '-c', str(count), '-W', str(timeout), host]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 5)
        output = proc.stdout
        
        latencies = []
        if system == 'windows':
            import re
            times = re.findall(r'time[=<](\d+)ms', output)
            latencies = [float(t) for t in times]
            loss_match = re.search(r'(\d+)%\s+loss', output)
            if loss_match:
                result['packet_loss'] = float(loss_match.group(1))
        else:
            import re
            times = re.findall(r'time=(\d+\.?\d*)\s*ms', output)
            latencies = [float(t) for t in times]
            loss_match = re.search(r'(\d+)%\s+packet\s+loss', output)
            if loss_match:
                result['packet_loss'] = float(loss_match.group(1))
        
        if latencies:
            result['reachable'] = True
            result['latency'] = sum(latencies) / len(latencies)
            if len(latencies) > 1:
                mean = result['latency']
                result['jitter'] = (sum((x - mean) ** 2 for x in latencies) / len(latencies)) ** 0.5
            else:
                result['jitter'] = 0.0
    except Exception:
        pass
    return result


def tcp_connect(host: str, port: int, timeout: int = 3) -> dict:
    result = {'open': False, 'latency': None}
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ret = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()
        if ret == 0:
            result['open'] = True
            result['latency'] = elapsed
    except Exception:
        pass
    return result


def tls_check(host: str, port: int = 443, timeout: int = 5) -> dict:
    result = {'success': False, 'cert_valid': False, 'sni_blocked': False, 'error': None}
    try:
        context = ssl.create_default_context()
        conn = socket.create_connection((host, port), timeout=timeout)
        tls_conn = context.wrap_socket(conn, server_hostname=host)
        cert = tls_conn.getpeercert()
        tls_conn.close()
        result['success'] = True
        result['cert_valid'] = True
    except ssl.SSLError as e:
        result['error'] = str(e)
        if 'CERTIFICATE_VERIFY_FAILED' in str(e):
            result['cert_valid'] = False
        if 'handshake' in str(e).lower() or 'reset' in str(e).lower():
            result['sni_blocked'] = True
    except ConnectionResetError:
        result['sni_blocked'] = True
        result['error'] = 'Connection Reset (possible DPI/filter)'
    except Exception as e:
        result['error'] = str(e)
    return result


def https_test(host: str, timeout: int = 10) -> dict:
    result = {
        'success': False, 'status_code': None, 'latency': None,
        'speed_kbps': None, 'dpi_detected': False, 'error': None
    }
    test_urls = [
        f'https://{host}/generate_204' if host not in ['8.8.8.8', '1.1.1.1', '8.8.4.4'] else 'https://www.google.com/generate_204',
        'https://www.google.com/generate_204',
        'https://1.1.1.1/',
    ]
    
    for url in test_urls:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            start = time.time()
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                elapsed = (time.time() - start) * 1000
                data = resp.read(65536)
                total_time = time.time() - start
                
                result['success'] = True
                result['status_code'] = resp.status
                result['latency'] = elapsed
                if total_time > 0 and len(data) > 0:
                    result['speed_kbps'] = (len(data) / 1024) / total_time
                break
        except urllib.error.HTTPError as e:
            result['status_code'] = e.code
            result['success'] = e.code in [200, 204, 301, 302]
            result['latency'] = (time.time() - start) * 1000 if 'start' in dir() else None
            break
        except ConnectionResetError:
            result['dpi_detected'] = True
            result['error'] = 'Connection Reset - DPI/Filter detected'
        except ssl.SSLError as e:
            if 'reset' in str(e).lower() or 'handshake' in str(e).lower():
                result['dpi_detected'] = True
            result['error'] = str(e)
        except Exception as e:
            result['error'] = str(e)
    
    return result


def traceroute(host: str, max_hops: int = 15, timeout: int = 3) -> dict:
    result = {'hops': 0, 'path': [], 'error': None}
    try:
        system = platform.system().lower()
        if system == 'windows':
            cmd = ['tracert', '-d', '-h', str(max_hops), '-w', str(timeout * 1000), host]
        else:
            cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', str(timeout), host]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * timeout + 10)
        lines = proc.stdout.strip().split('\n')
        
        import re
        hop_count = 0
        for line in lines:
            if re.search(r'^\s*\d+', line):
                hop_count += 1
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    result['path'].append(ip_match.group(1))
        
        result['hops'] = hop_count
    except Exception as e:
        result['error'] = str(e)
    return result


def scan_ip(ip: str, timeout: int = 3, do_traceroute: bool = False) -> dict:
    profile = {
        'ip': ip,
        'timestamp': datetime.now().isoformat(),
        'ping': {'reachable': False, 'latency': None, 'jitter': None, 'packet_loss': 100.0},
        'tcp_80': {'open': False, 'latency': None},
        'tcp_443': {'open': False, 'latency': None},
        'tls': {'success': False, 'cert_valid': False, 'sni_blocked': False, 'error': None},
        'https': {'success': False, 'status_code': None, 'latency': None, 'speed_kbps': None, 'dpi_detected': False},
        'traceroute': {'hops': 0, 'path': []},
        'overall_status': 'UNKNOWN',
        'healthy': False,
        'score': 0
    }
    
    ping_result = ping_host(ip, timeout=timeout, count=3)
    profile['ping'] = ping_result
    
    tcp80 = tcp_connect(ip, 80, timeout=timeout)
    profile['tcp_80'] = tcp80
    
    tcp443 = tcp_connect(ip, 443, timeout=timeout)
    profile['tcp_443'] = tcp443
    
    if tcp443['open']:
        tls_result = tls_check(ip, 443, timeout=timeout + 2)
        profile['tls'] = tls_result
    
    if tcp443['open'] or tcp80['open']:
        https_result = https_test(ip, timeout=timeout + 5)
        profile['https'] = https_result
    
    if do_traceroute and (ping_result['reachable'] or tcp443['open']):
        tr_result = traceroute(ip, max_hops=15, timeout=timeout)
        profile['traceroute'] = tr_result
    
    score = 0
    if ping_result['reachable']:
        score += 20
        if ping_result['latency'] and ping_result['latency'] < 100:
            score += 10
    if tcp80['open']:
        score += 15
    if tcp443['open']:
        score += 15
    if profile['tls']['success']:
        score += 20
    if profile['https']['success']:
        score += 20
        if profile['https']['speed_kbps'] and profile['https']['speed_kbps'] > 100:
            score += 10
    if profile['https']['dpi_detected'] or profile['tls']['sni_blocked']:
        score -= 30
    
    profile['score'] = max(0, score)
    profile['healthy'] = score >= 50
    
    if profile['https']['dpi_detected'] or profile['tls']['sni_blocked']:
        profile['overall_status'] = 'BLOCKED'
    elif profile['https']['success']:
        profile['overall_status'] = 'HEALTHY'
    elif tcp443['open'] or tcp80['open']:
        profile['overall_status'] = 'PARTIAL'
    elif ping_result['reachable']:
        profile['overall_status'] = 'PING_ONLY'
    else:
        profile['overall_status'] = 'UNREACHABLE'
    
    return profile


def parse_ip_ranges(text: str) -> list:
    ips = []
    lines = text.strip().split('\n')
    for line in lines:          # <-- this line was missing
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        parts = [p.strip() for p in line.split(',')]
        for part in parts:
            part = part.strip()
            if not part:
                continue
            try:
                if '/' in part:
                    network = ipaddress.ip_network(part, strict=False)
                    ips.extend([str(ip) for ip in network.hosts()])
                elif '-' in part:
                    start_ip, end_ip = part.split('-', 1)
                    start = ipaddress.ip_address(start_ip.strip())
                    end = ipaddress.ip_address(end_ip.strip())
                    current = start
                    while current <= end:
                        ips.append(str(current))
                        current += 1
                else:
                    ipaddress.ip_address(part)
                    ips.append(part)
            except ValueError:
                continue
    return list(dict.fromkeys(ips))

class ScanWorker(QThread):
    result_ready = pyqtSignal(dict)
    log_message = pyqtSignal(str)
    progress_update = pyqtSignal(int, int)
    scan_finished = pyqtSignal()

    def __init__(self, ips: list, timeout: int = 3, threads: int = 50, do_traceroute: bool = False):
        super().__init__()
        self.ips = ips
        self.timeout = timeout
        self.threads = threads
        self.do_traceroute = do_traceroute
        self._stop = False
        self._pause = False
        self._lock = threading.Lock()

    def stop(self):
        self._stop = True

    def pause(self):
        self._pause = True

    def resume(self):
        self._pause = False

    def run(self):
        total = len(self.ips)
        completed = 0

        def scan_one(ip):
            while self._pause:
                time.sleep(0.2)
            if self._stop:
                return None
            try:
                result = scan_ip(ip, timeout=self.timeout, do_traceroute=self.do_traceroute)
                return result
            except Exception as e:
                return {'ip': ip, 'error': str(e), 'overall_status': 'ERROR', 'healthy': False, 'score': 0}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_one, ip): ip for ip in self.ips}
            for future in as_completed(futures):
                if self._stop:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                result = future.result()
                if result:
                    with self._lock:
                        completed += 1
                    self.result_ready.emit(result)
                    self.progress_update.emit(completed, total)
                    status = result.get('overall_status', 'UNKNOWN')
                    self.log_message.emit(f"[{completed}/{total}] {result['ip']} → {status}")

        self.scan_finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings('IPScanner', 'App')
        self.current_lang = self.settings.value('language', 'en')
        self.current_theme = self.settings.value('theme', 'dark')
        self.results_data = []
        self.worker = None
        self.start_time = None
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.update_elapsed)

        self.setMinimumSize(900, 600)
        self.resize(int(self.settings.value('width', 1280)), int(self.settings.value('height', 800)))

        self.init_ui()
        self.apply_theme(self.current_theme)
        self.retranslate()

    def t(self, key: str) -> str:
        return TRANSLATIONS.get(self.current_lang, TRANSLATIONS['en']).get(key, key)

    def init_ui(self):
        self.setWindowTitle('IP Scanner')
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # Toolbar row
        toolbar_widget = QWidget()
        toolbar_layout = QHBoxLayout(toolbar_widget)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)

        self.title_label = QLabel()
        self.title_label.setFont(QFont('Segoe UI', 13, QFont.Weight.Bold))
        toolbar_layout.addWidget(self.title_label)
        toolbar_layout.addStretch()

        self.lang_label = QLabel()
        toolbar_layout.addWidget(self.lang_label)
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(['English', 'فارسی', '中文'])
        self.lang_combo.setCurrentIndex(['en', 'fa', 'zh'].index(self.current_lang))
        self.lang_combo.currentIndexChanged.connect(self.change_language)
        self.lang_combo.setFixedWidth(100)
        toolbar_layout.addWidget(self.lang_combo)

        self.theme_label = QLabel()
        toolbar_layout.addWidget(self.theme_label)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(['Dark', 'Light'])
        self.theme_combo.setCurrentIndex(0 if self.current_theme == 'dark' else 1)
        self.theme_combo.currentIndexChanged.connect(self.change_theme)
        self.theme_combo.setFixedWidth(80)
        toolbar_layout.addWidget(self.theme_combo)

        main_layout.addWidget(toolbar_widget)

        # Splitter: top config + bottom results
        splitter = QSplitter(Qt.Orientation.Vertical)
        main_layout.addWidget(splitter, 1)

        # Top panel
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(6)

        # IP input group
        self.ip_group = QGroupBox()
        ip_layout = QVBoxLayout(self.ip_group)
        self.ip_input = QTextEdit()
        self.ip_input.setPlaceholderText('192.168.1.0/24\n10.0.0.1-10.0.0.50\n8.8.8.8, 1.1.1.1')
        self.ip_input.setMaximumHeight(90)
        ip_layout.addWidget(self.ip_input)
        top_layout.addWidget(self.ip_group)

        # Settings row
        settings_widget = QWidget()
        settings_layout = QHBoxLayout(settings_widget)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(8)

        self.threads_label = QLabel()
        settings_layout.addWidget(self.threads_label)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(50)
        self.threads_spin.setFixedWidth(70)
        settings_layout.addWidget(self.threads_spin)

        self.timeout_label = QLabel()
        settings_layout.addWidget(self.timeout_label)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(3)
        self.timeout_spin.setFixedWidth(60)
        settings_layout.addWidget(self.timeout_spin)

        self.traceroute_check = QCheckBox()
        settings_layout.addWidget(self.traceroute_check)

        settings_layout.addStretch()

        self.start_btn = QPushButton()
        self.start_btn.setObjectName('startBtn')
        self.start_btn.setMinimumWidth(120)
        self.start_btn.clicked.connect(self.start_scan)
        settings_layout.addWidget(self.start_btn)

        self.pause_btn = QPushButton()
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.toggle_pause)
        settings_layout.addWidget(self.pause_btn)

        self.stop_btn = QPushButton()
        self.stop_btn.setObjectName('stopBtn')
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        settings_layout.addWidget(self.stop_btn)

        top_layout.addWidget(settings_widget)

        # Progress row
        progress_widget = QWidget()
        progress_layout = QHBoxLayout(progress_widget)
        progress_layout.setContentsMargins(0, 0, 0, 0)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar, 1)

        self.elapsed_label = QLabel('00:00')
        self.elapsed_label.setFixedWidth(55)
        progress_layout.addWidget(self.elapsed_label)

        self.progress_label = QLabel('0 / 0')
        self.progress_label.setFixedWidth(80)
        progress_layout.addWidget(self.progress_label)

        top_layout.addWidget(progress_widget)
        splitter.addWidget(top_widget)

        # Bottom tabs
        self.tabs = QTabWidget()

        # Results tab
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        results_layout.setContentsMargins(4, 4, 4, 4)

        # Filter/sort row
        filter_row = QWidget()
        filter_layout = QHBoxLayout(filter_row)
        filter_layout.setContentsMargins(0, 0, 0, 0)

        self.filter_label = QLabel()
        filter_layout.addWidget(self.filter_label)
        self.filter_input = QLineEdit()
        self.filter_input.setFixedWidth(160)
        self.filter_input.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input)

        self.sort_label = QLabel()
        filter_layout.addWidget(self.sort_label)
        self.sort_combo = QComboBox()
        self.sort_combo.setFixedWidth(140)
        self.sort_combo.currentIndexChanged.connect(self.apply_sort)
        filter_layout.addWidget(self.sort_combo)

        self.status_filter = QComboBox()
        self.status_filter.setFixedWidth(130)
        self.status_filter.currentIndexChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.status_filter)

        filter_layout.addStretch()

        self.export_json_btn = QPushButton()
        self.export_json_btn.clicked.connect(self.export_json)
        filter_layout.addWidget(self.export_json_btn)

        self.export_csv_btn = QPushButton()
        self.export_csv_btn.clicked.connect(self.export_csv)
        filter_layout.addWidget(self.export_csv_btn)

        self.clear_btn = QPushButton()
        self.clear_btn.clicked.connect(self.clear_results)
        filter_layout.addWidget(self.clear_btn)

        results_layout.addWidget(filter_row)

        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        results_layout.addWidget(self.table)

        self.tabs.addTab(results_tab, '')

        # Log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        log_layout.setContentsMargins(4, 4, 4, 4)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont('Consolas', 9))
        log_layout.addWidget(self.log_text)
        self.tabs.addTab(log_tab, '')

        # Summary tab
        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        summary_layout.setContentsMargins(4, 4, 4, 4)
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont('Consolas', 10))
        summary_layout.addWidget(self.summary_text)
        self.tabs.addTab(summary_tab, '')

        splitter.addWidget(self.tabs)
        splitter.setSizes([220, 500])

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Ready')

        self.setup_table_columns()
        self.setup_sort_combo()
        self.setup_status_filter()

    def setup_table_columns(self):
        columns = [
            'ip', 'ping', 'latency', 'jitter', 'packet_loss',
            'port_80', 'port_443', 'tls', 'https', 'speed',
            'traceroute', 'status'
        ]
        self.table_columns = columns
        self.table.setColumnCount(len(columns))
        self.update_table_headers()

    def update_table_headers(self):
        headers = [self.t(c) for c in self.table_columns]
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 130)

    def setup_sort_combo(self):
        self.sort_combo.clear()
        for key in ['latency', 'speed', 'packet_loss', 'score', 'ip']:
            self.sort_combo.addItem(self.t(key) if key != 'score' else 'Score', key)

    def setup_status_filter(self):
        self.status_filter.clear()
        self.status_filter.addItem('All', 'ALL')
        for s in ['HEALTHY', 'PARTIAL', 'PING_ONLY', 'BLOCKED', 'UNREACHABLE', 'ERROR']:
            self.status_filter.addItem(s, s)

    def retranslate(self):
        self.title_label.setText(self.t('title'))
        self.lang_label.setText(self.t('language') + ':')
        self.theme_label.setText(self.t('theme') + ':')
        self.ip_group.setTitle(self.t('ip_ranges'))
        self.ip_input.setPlaceholderText(self.t('ip_placeholder'))
        self.threads_label.setText(self.t('threads') + ':')
        self.timeout_label.setText(self.t('timeout') + ':')
        self.traceroute_check.setText(self.t('traceroute_test'))
        self.start_btn.setText(self.t('start_scan'))
        self.pause_btn.setText(self.t('pause'))
        self.stop_btn.setText(self.t('stop_scan'))
        self.filter_label.setText(self.t('filter') + ':')
        self.sort_label.setText(self.t('sort_by') + ':')
        self.export_json_btn.setText(self.t('export_json'))
        self.export_csv_btn.setText(self.t('export_csv'))
        self.clear_btn.setText(self.t('clear'))
        self.tabs.setTabText(0, self.t('results'))
        self.tabs.setTabText(1, self.t('log'))
        self.tabs.setTabText(2, self.t('summary'))
        self.update_table_headers()
        self.setup_sort_combo()

    def change_language(self, idx):
        langs = ['en', 'fa', 'zh']
        self.current_lang = langs[idx]
        self.settings.setValue('language', self.current_lang)
        self.retranslate()

    def change_theme(self, idx):
        self.current_theme = 'dark' if idx == 0 else 'light'
        self.settings.setValue('theme', self.current_theme)
        self.apply_theme(self.current_theme)

    def apply_theme(self, theme: str):
        if theme == 'dark':
            self.setStyleSheet(DARK_THEME)
        else:
            self.setStyleSheet(LIGHT_THEME)

    def start_scan(self):
        text = self.ip_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, 'Warning', 'Please enter IP ranges.')
            return

        ips = parse_ip_ranges(text)
        if not ips:
            QMessageBox.warning(self, 'Warning', 'No valid IPs found.')
            return

        if len(ips) > 65536:
            reply = QMessageBox.question(self, 'Large Scan',
                f'{len(ips)} IPs found. This may take a long time. Continue?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return

        self.results_data.clear()
        self.table.setRowCount(0)
        self.log_text.clear()
        self.summary_text.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(ips))

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.pause_btn.setEnabled(True)
        self.pause_btn.setText(self.t('pause'))

        self.start_time = time.time()
        self.scan_timer.start(1000)

        self.worker = ScanWorker(
            ips,
            timeout=self.timeout_spin.value(),
            threads=self.threads_spin.value(),
            do_traceroute=self.traceroute_check.isChecked()
        )
        self.worker.result_ready.connect(self.on_result)
        self.worker.log_message.connect(self.on_log)
        self.worker.progress_update.connect(self.on_progress)
        self.worker.scan_finished.connect(self.on_finished)
        self.worker.start()

        self.status_bar.showMessage(self.t('scanning') + f' {len(ips)} IPs')

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
        self.scan_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)

    def toggle_pause(self):
        if not self.worker:
            return
        if self.worker._pause:
            self.worker.resume()
            self.pause_btn.setText(self.t('pause'))
            self.scan_timer.start(1000)
        else:
            self.worker.pause()
            self.pause_btn.setText(self.t('resume'))
            self.scan_timer.stop()

    def on_result(self, result: dict):
        self.results_data.append(result)
        self.add_table_row(result)

    def on_log(self, msg: str):
        self.log_text.append(msg)

    def on_progress(self, done: int, total: int):
        self.progress_bar.setValue(done)
        self.progress_label.setText(f'{done} / {total}')

    def on_finished(self):
        self.scan_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)
        self.status_bar.showMessage(self.t('done'))
        self.update_summary()

    def update_elapsed(self):
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            m, s = divmod(elapsed, 60)
            self.elapsed_label.setText(f'{m:02d}:{s:02d}')

    def add_table_row(self, r: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)

        def cell(text, color=None):
            item = QTableWidgetItem(str(text) if text is not None else '-')
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if color:
                item.setForeground(QColor(color))
            return item

        ping = r.get('ping', {})
        tcp80 = r.get('tcp_80', {})
        tcp443 = r.get('tcp_443', {})
        tls = r.get('tls', {})
        https = r.get('https', {})
        tr = r.get('traceroute', {})
        status = r.get('overall_status', 'UNKNOWN')

        status_colors = {
            'HEALTHY': '#2ecc71',
            'PARTIAL': '#f39c12',
            'PING_ONLY': '#e67e22',
            'BLOCKED': '#e74c3c',
            'UNREACHABLE': '#95a5a6',
            'ERROR': '#e74c3c',
            'UNKNOWN': '#bdc3c7',
        }

        ping_ok = ping.get('reachable', False)
        lat = ping.get('latency')
        jit = ping.get('jitter')
        loss = ping.get('packet_loss', 100)
        speed = https.get('speed_kbps')
        hops = tr.get('hops', 0)

        self.table.setItem(row, 0, cell(r.get('ip', '-')))
        self.table.setItem(row, 1, cell('✓' if ping_ok else '✗', '#2ecc71' if ping_ok else '#e74c3c'))
        self.table.setItem(row, 2, cell(f'{lat:.1f}' if lat else '-', '#2ecc71' if lat and lat < 100 else '#f39c12' if lat else None))
        self.table.setItem(row, 3, cell(f'{jit:.1f}' if jit is not None else '-'))
        self.table.setItem(row, 4, cell(f'{loss:.0f}%', '#2ecc71' if loss == 0 else '#e74c3c' if loss == 100 else '#f39c12'))
        self.table.setItem(row, 5, cell('✓' if tcp80.get('open') else '✗', '#2ecc71' if tcp80.get('open') else '#e74c3c'))
        self.table.setItem(row, 6, cell('✓' if tcp443.get('open') else '✗', '#2ecc71' if tcp443.get('open') else '#e74c3c'))
        self.table.setItem(row, 7, cell('✓' if tls.get('success') else ('DPI' if tls.get('sni_blocked') else '✗'),
                                        '#2ecc71' if tls.get('success') else '#e74c3c'))
        https_text = str(https.get('status_code', '-')) if https.get('success') else ('DPI' if https.get('dpi_detected') else '✗')
        self.table.setItem(row, 8, cell(https_text, '#2ecc71' if https.get('success') else '#e74c3c'))
        self.table.setItem(row, 9, cell(f'{speed:.1f}' if speed else '-', '#2ecc71' if speed and speed > 100 else None))
        self.table.setItem(row, 10, cell(str(hops) if hops else '-'))
        self.table.setItem(row, 11, cell(status, status_colors.get(status, '#bdc3c7')))

    def apply_filter(self):
        filter_text = self.filter_input.text().lower()
        status_filter = self.status_filter.currentData()

        for row in range(self.table.rowCount()):
            ip_item = self.table.item(row, 0)
            status_item = self.table.item(row, 11)
            if not ip_item:
                continue
            ip_text = ip_item.text().lower()
            status_text = status_item.text() if status_item else ''

            show = True
            if filter_text and filter_text not in ip_text:
                show = False
            if status_filter and status_filter != 'ALL' and status_text != status_filter:
                show = False

            self.table.setRowHidden(row, not show)

    def apply_sort(self):
        sort_key = self.sort_combo.currentData()
        if not sort_key or not self.results_data:
            return

        def sort_val(r):
            if sort_key == 'latency':
                v = r.get('ping', {}).get('latency')
                return v if v is not None else 9999
            elif sort_key == 'speed':
                v = r.get('https', {}).get('speed_kbps')
                return -(v if v is not None else 0)
            elif sort_key == 'packet_loss':
                return r.get('ping', {}).get('packet_loss', 100)
            elif sort_key == 'score':
                return -r.get('score', 0)
            elif sort_key == 'ip':
                try:
                    return int(ipaddress.ip_address(r.get('ip', '0.0.0.0')))
                except Exception:
                    return 0
            return 0

        self.results_data.sort(key=sort_val)
        self.table.setRowCount(0)
        for r in self.results_data:
            self.add_table_row(r)

    def update_summary(self):
        total = len(self.results_data)
        healthy = sum(1 for r in self.results_data if r.get('healthy'))
        blocked = sum(1 for r in self.results_data if r.get('overall_status') == 'BLOCKED')
        reachable = sum(1 for r in self.results_data if r.get('ping', {}).get('reachable'))
        https_ok = sum(1 for r in self.results_data if r.get('https', {}).get('success'))

        latencies = [r['ping']['latency'] for r in self.results_data if r.get('ping', {}).get('latency')]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0

        speeds = [r['https']['speed_kbps'] for r in self.results_data if r.get('https', {}).get('speed_kbps')]
        avg_speed = sum(speeds) / len(speeds) if speeds else 0

        healthy_ips = [r['ip'] for r in self.results_data if r.get('healthy')]

        summary = f"""{'='*50}
SCAN SUMMARY
{'='*50}
Total Scanned  : {total}
Healthy IPs    : {healthy}
Reachable      : {reachable}
HTTPS Success  : {https_ok}
Blocked/DPI    : {blocked}
Avg Latency    : {avg_lat:.1f} ms
Avg Speed      : {avg_speed:.1f} KB/s
{'='*50}
HEALTHY IPs ({len(healthy_ips)}):
{chr(10).join(healthy_ips) if healthy_ips else 'None'}
{'='*50}
"""
        self.summary_text.setPlainText(summary)
        self.status_bar.showMessage(
            f"{self.t('done')} | {self.t('total')}: {total} | {self.t('healthy')}: {healthy}"
        )

    def export_json(self):
        if not self.results_data:
            QMessageBox.information(self, 'Info', 'No data to export.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Save JSON', 'scan_results.json', 'JSON Files (*.json)')
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.results_data, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, 'Exported', f'Saved to {path}')

    def export_csv(self):
        if not self.results_data:
            QMessageBox.information(self, 'Info', 'No data to export.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Save CSV', 'scan_results.csv', 'CSV Files (*.csv)')
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'IP', 'Ping', 'Latency_ms', 'Jitter_ms', 'PacketLoss_%',
                    'Port80', 'Port443', 'TLS', 'HTTPS', 'Speed_KBps',
                    'Hops', 'Status', 'Score', 'Healthy'
                ])
                for r in self.results_data:
                    ping = r.get('ping', {})
                    writer.writerow([
                        r.get('ip', ''),
                        ping.get('reachable', False),
                        ping.get('latency', ''),
                        ping.get('jitter', ''),
                        ping.get('packet_loss', ''),
                        r.get('tcp_80', {}).get('open', False),
                        r.get('tcp_443', {}).get('open', False),
                        r.get('tls', {}).get('success', False),
                        r.get('https', {}).get('success', False),
                        r.get('https', {}).get('speed_kbps', ''),
                        r.get('traceroute', {}).get('hops', ''),
                        r.get('overall_status', ''),
                        r.get('score', 0),
                        r.get('healthy', False),
                    ])
            QMessageBox.information(self, 'Exported', f'Saved to {path}')

    def clear_results(self):
        reply = QMessageBox.question(self, 'Clear', 'Clear all results?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.results_data.clear()
            self.table.setRowCount(0)
            self.log_text.clear()
            self.summary_text.clear()
            self.progress_bar.setValue(0)
            self.progress_label.setText('0 / 0')
            self.elapsed_label.setText('00:00')
            self.status_bar.showMessage('Ready')

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
        self.settings.setValue('width', self.width())
        self.settings.setValue('height', self.height())
        self.settings.setValue('theme', self.current_theme)
        self.settings.setValue('language', self.current_lang)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('IP Scanner')
    app.setOrganizationName('IPScanner')

    # High DPI support
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        app.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
