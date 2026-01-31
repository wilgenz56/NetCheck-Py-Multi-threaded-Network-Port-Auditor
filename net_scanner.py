import scapy.all as scapy
import argparse
from concurrent.futures import ThreadPoolExecutor
import socket # Usiamo socket per la scansione porte: è più veloce di Scapy per i connect scan

# Lista delle porte comuni da controllare (puoi espanderla)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080]

def check_port(ip, port):
    """
    Tenta di aprire una connessione TCP su una specifica porta.
    """
    try:
        # Creiamo un socket TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Tempo massimo di attesa mezzo secondo
        result = sock.connect_ex((ip, port)) # Restituisce 0 se la porta è aperta
        if result == 0:
            return port
        sock.close()
    except:
        pass
    return None

def scan_ip(ip):
    """ ARP Scan per trovare l'host """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        found_ip = answered_list[0][1].psrc
        found_mac = answered_list[0][1].hwsrc
        
        # Una volta trovato l'host, cerchiamo le porte aperte
        open_ports = []
        # Usiamo un piccolo thread pool interno per non rallentare troppo
        with ThreadPoolExecutor(max_workers=20) as port_executor:
            port_results = [port_executor.submit(check_port, found_ip, p) for p in COMMON_PORTS]
            for r in port_results:
                p_val = r.result()
                if p_val:
                    open_ports.append(str(p_val))
        
        return {"ip": found_ip, "mac": found_mac, "ports": open_ports}
    return None

def run_scanner(network_range, threads):
    print(f"[*] Audit avviato su: {network_range}")
    print(f"[*] Scansione host e porte comuni in corso...")
    print("-" * 65)
    print(f"{'IP Address':<15} | {'MAC Address':<18} | {'Open Ports'}")
    print("-" * 65)

    ips = [str(ip) for ip in scapy.Net(network_range)]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(scan_ip, ips)

    for result in results:
        if result:
            ports_str = ", ".join(result['ports']) if result['ports'] else "Nessuna porta aperta trovata"
            print(f"{result['ip']:<15} | {result['mac']:<18} | {ports_str}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network & Port Scanner for Security Auditing")
    parser.add_argument("-t", "--target", dest="target", help="Range IP (es. 192.168.1.0/24)", required=True)
    parser.add_argument("-w", "--workers", dest="workers", help="Thread per host (default: 10)", type=int, default=10)
    
    args = parser.parse_args()
    
    try:
        run_scanner(args.target, args.workers)
    except KeyboardInterrupt:
        print("\n[!] Operazione interrotta.")