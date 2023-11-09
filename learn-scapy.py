from scapy.all import *
from flask import Flask, jsonify
from threading import Thread

app = Flask(__name__)

# Membuat dictionary untuk menyimpan waktu awal setiap IP dan total durasinya
ip_statistics = {}
idx = 0
last_ip = "tidak ada"
# Menerima paket dengan menggunakan Sniff dalam thread terpisah
def start_sniffing():
    sniff(prn=process_packet)  # ganti 'count' sesuai kebutuhan Anda

# Fungsi untuk memproses paket
def process_packet(pkt):
    global last_ip
    global idx
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        packet_size = len(pkt)
        protocol_num = pkt[IP].proto  # Mengambil nomor protokol
        protocol_name = {
            1: "icmp",
            6: "tcp",
            17: "udp"
        }
        protocol = protocol_name[protocol_num]
        service = "Unknown"
        if TCP in pkt:
            port = pkt[TCP].dport
            try:
                service = socket.getservbyport(port, 'tcp')  # Mengambil informasi layanan dari port TCP
            except:
                service = "Unknown"
        elif UDP in pkt:
            port = pkt[UDP].dport
            try:
                service = socket.getservbyport(port, 'udp')  # Mengambil informasi layanan dari port UDP
            except:
                service = "Unknown"
        if(last_ip == src_ip):
            ip_statistics[idx] = {
                "ip_src": ip_statistics[idx]["ip_src"],
                "ip_dst": ip_statistics[idx]["ip_dst"],
                "start_time": ip_statistics[idx]["start_time"],
                "duration": pkt.time - ip_statistics[idx]["start_time"],
                "pkt_len": ip_statistics[idx]["pkt_len"] + packet_size,
                "protocol": protocol,
                "service": service
            }
        else:
            idx = idx + 1
            ip_statistics[idx] = {
                "ip_src": src_ip,
                "ip_dst": dst_ip,
                "start_time": pkt.time,
                "duration": 0,
                "pkt_len": packet_size,
                "protocol": protocol,
                "service": service
            }
        last_ip = src_ip
        
# Route untuk mengambil data statistik IP
@app.route('/ip_statistics', methods=['GET'])
def get_ip_statistics():
    print(last_ip)
    return jsonify(ip_statistics)

# # Fungsi untuk menjalankan aplikasi Flask dalam thread terpisah
def start_flask_app():
    app.run(host='0.0.0.0', debug=True, use_reloader=False)

# Membuat dan memulai thread untuk Scapy
scapy_thread = Thread(target=start_sniffing)
scapy_thread.start()

# Membuat dan memulai thread untuk Flask
flask_thread = Thread(target=start_flask_app)
flask_thread.start()

# old logic
# request_key = f"{src_ip}-{dst_ip}"
# print(request_key)
# if request_key not in ip_statistics:
#     ip_statistics[request_key] = {"start_time": pkt.time, "duration": 0, "total_packet_size": packet_size, "destination_ips": {dst_ip: packet_size}}
# else:
#     ip_statistics[request_key]["ip_src"] = src_ip
#     ip_statistics[request_key]["ip_dst"] = dst_ip
#     duration = pkt.time - ip_statistics[request_key]["start_time"]
#     ip_statistics[request_key]["duration"] += duration
#     ip_statistics[request_key]["total_packet_size"] += packet_size
#     if dst_ip in ip_statistics[request_key]["destination_ips"]:
#         ip_statistics[request_key]["destination_ips"][dst_ip] += packet_size
#     else:
#         ip_statistics[request_key]["destination_ips"][dst_ip] = packet_size
#     ip_statistics[request_key]["start_time"] = pkt.time