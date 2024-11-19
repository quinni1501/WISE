# -*- coding: utf-8 -*-
"""
Created on Fri Nov 15 20:00:42 2024

@author: ADMIN
"""
# d4:01:c3:2f:d3:dc
from scapy.all import ARP, sniff, send
import ctypes  # Dùng để hiển thị message box trên Windows

# Tạo bảng ARP tĩnh (IP và MAC thật)
ARP_TABLE = {}

def detect_and_fix_arp_spoof(pkt):
    """Phát hiện ARP Spoofing và thực hiện khắc phục"""
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc

        # Nếu IP đã biết nhưng MAC khác
        if ip_src in ARP_TABLE and mac_src != ARP_TABLE[ip_src]:
            print(f"\n[ALERT] ARP Spoofing Detected!")
            print(f"- Suspicious IP: {ip_src}")
            print(f"- Fake MAC: {mac_src}")
            print(f"- Expected MAC: {ARP_TABLE[ip_src]}")

            # Hiển thị message box cảnh báo
            message = f"ARP Spoofing Detected!\nIP: {ip_src}\nFake MAC: {mac_src}\nExpected MAC: {ARP_TABLE[ip_src]}"
            ctypes.windll.user32.MessageBoxW(0, message, "ARP Spoofing Alert", 0x40 | 0x1)

            # Khôi phục bảng ARP
            restore_arp(ip_src, ARP_TABLE[ip_src])

def restore_arp(ip, mac):
    """Gửi gói ARP Reply để khôi phục ánh xạ đúng"""
    pkt = ARP(op=2, psrc=ip, hwsrc=mac, pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff")
    send(pkt, verbose=False)
    print(f"[INFO] Restored ARP entry for {ip} -> {mac}")

def main():
    print("### ARP Spoofing Detection and Protection Tool ###")
    print("Nhập thông tin mạng của bạn để bắt đầu:")
    
    # Người dùng nhập IP và MAC của Gateway
    gateway_ip = input("Nhập Gateway IP (VD: 192.168.1.1): ").strip()
    gateway_mac = input("Nhập Gateway MAC (VD: 00:11:22:33:44:55): ").strip()

    # Lưu vào bảng ARP
    ARP_TABLE[gateway_ip] = gateway_mac
    print(f"\n[INFO] Bảng ARP khởi tạo: {ARP_TABLE}")
    print("[INFO] Đang giám sát gói tin ARP...")

    # Bắt gói tin ARP và kiểm tra
    sniff(filter="arp", prn=detect_and_fix_arp_spoof, store=0)

if __name__ == "__main__":
    main()
