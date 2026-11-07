#!/usr/bin/env python3
"""
netscan.py — Akıllı Ağ Keşif ve Çok İş Parçacıklı TCP Port Tarayıcı.
Önce ağdaki aktif cihazları hızlıca keşfeder, ardından SADECE aktif cihazları tarar.
Kullanım örneği
python3 netscan.py <Hedef IP>
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime

# Yaygın portlara mobil ve IoT servisleri de eklendi
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    5555: "ADB (Android)", 8008: "Chromecast", 8009: "GoogleCast"
}

@dataclass
class OpenPort:
    host: str
    port: int
    service: str
    banner: str

def parse_ports(port_arg: str) -> list[int]:
    ports: set[int] = set()
    for chunk in port_arg.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif chunk:
            ports.add(int(chunk))
    if not ports:
        raise ValueError("Geçerli bir port belirtilmedi.")
    return sorted(p for p in ports if 0 < p <= 65535)

def resolve_targets(target: str) -> list[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()]
        return [str(network.network_address)]
    except ValueError:
        return [target]

def ping_host(host: str, timeout: float) -> str | None:
    """
    Cihazın ağda canlı olup olmadığını anlamak için yaygın yönetim portlarına bakar.
    Kapalı port olsa bile cihaz 'buna yetkim yok/kapalıyım' diye cevap dönerse 
    cihazın CANLI olduğu anlaşılır (zaman aşımına düşmez).
    """
    check_ports = [80, 443, 22, 135, 445]
    for port in check_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                # 0: Açık port, diğer kodlar (111, 61 vb.): Cihaz canlı ama port kapalı mesajıdır
                if result == 0 or result in (111, 61, 10061):
                    return host
        except Exception:
            continue
    return None

def discover_active_hosts(targets: list[str], threads: int, timeout: float) -> list[str]:
    active_hosts = []
    print(f"[*] 1. ADIM: Ağdaki aktif cihazlar keşfediliyor (Cihaz Bulma)...")
    
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(ping_host, host, timeout): host for host in targets}
        for future in as_completed(futures):
            res = future.result()
            if res:
                active_hosts.append(res)
                print(f"  [+] Canlı Cihaz Tespit Edildi: {res}")
                
    return sorted(active_hosts, key=lambda ip: ipaddress.ip_address(ip))

def grab_banner(sock: socket.socket, port: int) -> str:
    try:
        sock.settimeout(1.0)
        if port in (80, 8080, 8000):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: scan\r\nConnection: close\r\n\r\n")
        data = sock.recv(256)
        return data.decode(errors="replace").strip().splitlines()[0] if data else ""
    except Exception:
        return ""

def scan_port(host: str, port: int, timeout: float) -> OpenPort | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result != 0:
                return None
            service = COMMON_PORTS.get(port, "bilinmiyor")
            banner = grab_banner(sock, port)
            return OpenPort(host=host, port=port, service=service, banner=banner)
    except (socket.gaierror, OSError):
        return None

def scan_host(host: str, ports: list[int], threads: int, timeout: float) -> list[OpenPort]:
    open_ports: list[OpenPort] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports, key=lambda r: r.port)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Önce Canlı Cihaz Keşfeden, Sonra Port Tarayan Akıllı Port Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="IP, hostname veya CIDR (örn. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port aralığı/listesi")
    parser.add_argument("-t", "--threads", type=int, default=150, help="Aynı anda kaç thread")
    parser.add_argument("--timeout", type=float, default=0.2, help="Zaman aşımı süresi")
    parser.add_argument("--json", metavar="DOSYA", help="Sonuçları JSON olarak kaydet")
    parser.add_argument("--csv", metavar="DOSYA", help="Sonuçları CSV olarak kaydet")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Hata: {e}", file=sys.stderr)
        sys.exit(1)

    targets = resolve_targets(args.target)
    print(f"[+] Toplam {len(targets)} olası IP adresi incelenecek.\n")

    start_time = time.time()
    
    # 1. ADIM: Önce ağdaki aktif kişileri buluyoruz
    active_hosts = discover_active_hosts(targets, args.threads, args.timeout)
    
    print(f"\n[*] Keşif Tamamlandı. Toplam {len(active_hosts)} aktif cihaz bulundu.")
    print(f"[*] 2. ADIM: Sadece aktif cihazlar üzerinde detaylı port taraması başlatılıyor...\n")

    all_results: list[OpenPort] = []

    # 2. ADIM: Sadece canlı olan cihazları tek tek analiz ediyoruz
    for host in active_hosts:
        print(f"--- {host} Analiz Ediliyor ---")
        results = scan_host(host, ports, args.threads, args.timeout)
        if not results:
            print("  (Cihaz açık ancak taranan port aralığında açık kapı bulunamadı)")
        for r in results:
            banner_part = f"  → {r.banner}" if r.banner else ""
            print(f"  {r.port:>5}/tcp  open  {r.service:<12}{banner_part}")
        all_results.extend(results)
        print()

    elapsed = time.time() - start_time
    print(f"[+] Akıllı tarama tamamlandı: {len(active_hosts)} cihazda {len(all_results)} açık port bulundu.")
    print(f"[+] Toplam süre: {elapsed:.2f} saniye")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in all_results], f, indent=2, ensure_ascii=False)
        print(f"[+] JSON rapor kaydedildi: {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["host", "port", "service", "banner"])
            writer.writeheader()
            for r in all_results:
                writer.writerow(asdict(r))
        print(f"[+] CSV rapor kaydedildi: {args.csv}")

if __name__ == "__main__":
    main()
