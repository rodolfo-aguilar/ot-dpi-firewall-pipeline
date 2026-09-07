import os
import sys
import logging
from scapy.all import sniff, IP, TCP

# --- FORENSIC LOGGING CONFIGURATION ---
LOG_FILE = "/Users/rodolfoaguilar/Documents/Projects/otcybersecurity/logs/dpi_firewall_violations.log"

# Set up logging format to capture precise timestamps, alert levels, and messages
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout) # This keeps the terminal printing live while writing to disk
    ]
)

# --- DEFENSIVE POLICY PROFILE ---
AUTHORIZED_OPERATOR_IP = "192.168.1.100"
PLC_PORT = 502                            
DANGEROUS_WRITE_COMMANDS = [5, 6, 15, 16]

def inspect_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        if tcp_layer.dport == PLC_PORT:
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            raw_payload = bytes(tcp_layer.payload)
            
            if len(raw_payload) >= 8:
                modbus_function_code = raw_payload[7]
                
                # RULE 1: UNAUTHORIZED IP ACCESS ATTEMPT
                if src_ip != AUTHORIZED_OPERATOR_IP:
                    logging.critical(
                        f"[❌ BLOCK] IP VIOLATION: Unauthorized source IP {src_ip} "
                        f"attempted to access PLC ({dst_ip}) on Port {PLC_PORT}. "
                        f"Attempted Modbus Code: {modbus_function_code}"
                    )
                    return

                # RULE 2: DEEP PACKET INSPECTION (DPI) VIOLATION
                if modbus_function_code in DANGEROUS_WRITE_COMMANDS:
                    logging.critical(
                        f"[❌ BLOCK] INDUSTRIAL POLICY VIOLATION: Authorized Operator ({src_ip}) "
                        f"sent dangerous WRITE command (Code: {modbus_function_code}) to PLC ({dst_ip})!"
                    )
                    return
                
                # Traffic is read-only and from a trusted host
                logging.info(f"[✅ ALLOW] Valid read command from {src_ip} -> Modbus Code: {modbus_function_code}")

def main():
    logging.info("Starting DPI Firewall Engine...")
    logging.info(f"Writing forensic alerts to: {LOG_FILE}")
    logging.info("-" * 70)
    
    try:
        sniff(filter=f"tcp port {PLC_PORT}", prn=inspect_packet, store=0)
    except PermissionError:
        print("[-] Error: You must run this script with 'sudo' to sniff network cards and write to system logs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
