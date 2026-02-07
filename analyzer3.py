#!/usr/bin/env python3
"""
Анализ HTTP-трафика Gruyere + онлайн-вывод + сохранение в JSON и PCAP
"""

from scapy.all import AsyncSniffer, IP, TCP, Raw, wrpcap
from datetime import datetime
import json
import sys
import time
import os

requests = []
responses = []
captured_packets = []           # ← для сохранения в .pcap

def analyze_packet(packet):
    # Сохраняем пакет в список для последующего дампа
    captured_packets.append(packet)

    if not (IP in packet and TCP in packet and Raw in packet):
        return

    payload_bytes = bytes(packet[Raw].load)
    
    try:
        decoded = payload_bytes.decode('utf-8', errors='ignore').rstrip('\x00').strip()
        
        if not decoded:
            return

        src = f"{packet[IP].src}:{packet[TCP].sport}"
        dst = f"{packet[IP].dst}:{packet[TCP].dport}"

        # REQUEST
        if decoded.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'OPTIONS ', 'DELETE ', 'PATCH ')):
            lines = decoded.splitlines()
            req_line = lines[0].strip()
            print(f"  ┌─ [REQUEST]  {req_line}")
            print(f"  └─ {src} → {dst}")
            
            requests.append({
                'type': 'REQUEST',
                'data': req_line,
                'src': src,
                'dst': dst,
                'time': datetime.now().isoformat()
            })

        # RESPONSE
        elif decoded.startswith('HTTP/'):
            lines = decoded.splitlines()
            resp_line = lines[0].strip()
            print(f"  ┌─ [RESPONSE] {resp_line}")
            print(f"  └─ {src} → {dst}")
            
            responses.append({
                'type': 'RESPONSE',
                'data': resp_line,
                'src': src,
                'dst': dst,
                'time': datetime.now().isoformat()
            })

    except Exception:
        pass


# ────────────────────────────────────────────────
print("=" * 78)
print(" GRUYERE TRAFFIC CAPTURE → JSON + PCAP")
print("=" * 78)
print(" http://google-gruyere.appspot.com")
print(" Делайте действия в браузере → увидите запросы/ответы в реальном времени")
print(" Ctrl+C → сохранение результатов и дампа трафика\n")

# ─── Настройки ───────────────────────────────────
IFACE  = "wlan0"               # изменяется в зависимости от интерфейса вручную
FILTER = "tcp port 80"        # только HTTP (443 — TLS, смысла мало)

PCAP_FILENAME = f"gruyere_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
JSON_FILENAME = "gruyere_traffic.json"

# ─── Запуск ──────────────────────────────────────
sniffer = AsyncSniffer(
    iface=IFACE,
    filter=FILTER,
    prn=analyze_packet,
    store=False,                  # не храним в памяти дважды
    promisc=True
)

try:
    print(f"Перехват на интерфейсе: {IFACE} | фильтр: {FILTER}")
    print("Ожидание трафика...\n")
    
    sniffer.start()
    
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n" + "═" * 40 + " ОСТАНОВКА " + "═" * 40)
    
    sniffer.stop()
    sniffer.join(timeout=3.0)

    print(f"\nПерехвачено запросов : {len(requests):4d}")
    print(f"Перехвачено ответов  : {len(responses):4d}")
    print(f"Всего пакетов        : {len(captured_packets):4d}")

    # 1. Сохранение JSON
    data = {
        'timestamp_start': datetime.now().isoformat(),
        'total_requests': len(requests),
        'total_responses': len(responses),
        'requests': requests,
        'responses': responses
    }

    try:
        with open(JSON_FILENAME, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"JSON сохранён → {JSON_FILENAME}")
    except Exception as e:
        print(f"Ошибка сохранения JSON: {e}")

    # 2. Сохранение PCAP
    if captured_packets:
        try:
            wrpcap(PCAP_FILENAME, captured_packets)
            size_mb = os.path.getsize(PCAP_FILENAME) / (1024 * 1024)
            print(f"PCAP сохранён   → {PCAP_FILENAME}  ({size_mb:.1f} MiB)")
        except Exception as e:
            print(f"Ошибка сохранения PCAP: {e}")
    else:
        print("PCAP не сохранён — пакетов не было")

    print("\nГотово. Можете открыть .pcap в Wireshark.")
    sys.exit(0)

except Exception as e:
    print(f"\nКритическая ошибка: {e}")
    if sniffer.running:
        sniffer.stop()
        sniffer.join(timeout=2.0)
    sys.exit(1)
