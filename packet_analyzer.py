import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer GUI")
        self.sniffing = False
        self.sniffer_thread = None
        self.packet_count = tk.StringVar(value="10")

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.X)

        ttk.Label(frame, text="Packets to capture (0 = continuous):").pack(side=tk.LEFT)
        self.count_entry = ttk.Entry(frame, width=8, textvariable=self.packet_count)
        self.count_entry.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.text_area = scrolledtext.ScrolledText(self.root, width=100, height=30, state=tk.DISABLED)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def log(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)
        self.text_area.config(state=tk.DISABLED)

    def packet_callback(self, packet):
        if not packet.haslayer(IP):
            return
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "Unknown"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = f"Other({packet[IP].proto})"
        self.log(f"[+] Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            try:
                decoded_payload = payload.decode('utf-8', 'replace')
                self.log(f"    Payload: {decoded_payload}")
            except Exception:
                self.log(f"    Payload (raw bytes): {payload[:80]}...")

    def sniff_packets(self, count):
        try:
            self.log("\n[INFO] Starting network sniffer... Press 'Stop' to end.")
            self.sniffing = True
            scapy.sniff(prn=self.packet_callback, store=False, count=count if count > 0 else 0, stop_filter=lambda x: not self.sniffing)
        except PermissionError:
            self.log("[ERROR] Permission denied. Please run as administrator/root.")
        except Exception as e:
            self.log(f"[ERROR] {e}")
        finally:
            self.sniffing = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.log("[INFO] Sniffer stopped.")

    def start_sniffing(self):
        try:
            count = int(self.packet_count.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid integer for packet count.")
            return
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(count,), daemon=True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.stop_btn.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.NORMAL)
        self.log("[INFO] Stopping sniffer...")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop() 
