import pandas as pd
from flask import Flask, request, jsonify, render_template
import pickle
import pymysql.cursors
from scapy.all import *
from threading import Thread

# Initialize Flask app
app = Flask(__name__)

# Atur secret key
app.secret_key = b"\xa5\x90\xf6\x87\x03E\xc0#t\x05\xeb1Q\x81RH\x83'5;\xddY\xc9o"

# Membuat dictionary untuk menyimpan waktu awal setiap IP dan total durasinya
ip_statistics = {}
idx = 0
last_ip = "tidak ada"

# Load the trained Random Forest model
with open('rf_nsl_with_hyperparams_model.pkl', 'rb') as f:
    model = pickle.load(f)

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
        service = "http"
        if TCP in pkt:
            port = pkt[TCP].dport
            try:
                service = socket.getservbyport(port, 'tcp')  # Mengambil informasi layanan dari port TCP
            except:
                service = "http"
        elif UDP in pkt:
            port = pkt[UDP].dport
            try:
                service = socket.getservbyport(port, 'udp')  # Mengambil informasi layanan dari port UDP
            except:
                service = "http"
        if(service == "ssh"): service = "http"
        if(last_ip == src_ip):
            ip_statistics[idx] = {
                "ip_src": ip_statistics[idx]["ip_src"],
                "ip_dst": ip_statistics[idx]["ip_dst"],
                "start_time": ip_statistics[idx]["start_time"],
                "duration": pkt.time - ip_statistics[idx]["start_time"],
                "src_bytes": ip_statistics[idx]["src_bytes"] + packet_size,
                "dst_bytes": ip_statistics[idx]["src_bytes"] + packet_size,
                "protocol_type": protocol,
                "service": service
            }
        else:
            idx = idx + 1
            ip_statistics[idx] = {
                "ip_src": src_ip,
                "ip_dst": dst_ip,
                "start_time": pkt.time,
                "duration": 0,
                "src_bytes": packet_size,
                "dst_bytes": packet_size,
                "protocol_type": protocol,
                "service": service
            }
            if(idx == 1):
                predict_data(ip_statistics[idx])
            else:
                predict_data(ip_statistics[idx - 1])

        last_ip = src_ip

def predict_data(data):
    df = pd.DataFrame([{
        'duration': data['duration'],
        'protocol_type': data['protocol_type'],
        'service': data['service'],
        'src_bytes': data['src_bytes'],
        'dst_bytes': data['dst_bytes'],
    }])
    prediction = int(model.predict(df)[0])
    
    print(data['protocol_type'], data['service'])

    connection = pymysql.connect(host='localhost',
                                    user='cemilick',
                                    password='cemilick',
                                    db='intrusion_detection',
                                    charset='utf8mb4',
                                    cursorclass=pymysql.cursors.DictCursor)
    
    with connection.cursor() as cursor:
        sql = "INSERT INTO `intrusion_data` (`ip_address`, `prediction`, `pkt_len`, `duration`) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (data['ip_src'], prediction, data['src_bytes'], data['duration']))

    connection.commit()
    connection.close()

@app.route('/getIntrusions', methods=['GET'])
def get_intrusions():
    try:
        connection = pymysql.connect(host='localhost',
                                     user='cemilick',
                                     password='cemilick',
                                     db='intrusion_detection',
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)
        
        with connection.cursor() as cursor:
            sql = "SELECT * FROM `intrusion_data`"
            cursor.execute(sql)
            intrusions = cursor.fetchall()

        connection.close()

        return jsonify({'intrusions': intrusions})

    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/')
def dashboard():
    # get data pengakses
    return render_template('dashboard.html')


@app.route('/getLocalIp')
def getIp():
    return request.remote_addr


@app.route('/clear')
def clearData():
    # Membuka koneksi ke MySQL
    connection = pymysql.connect(
        host='localhost',
        user='cemilick',
        password='cemilick',
        db='intrusion_detection',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

    try:
        with connection.cursor() as cursor:
            # Perintah DELETE untuk menghapus semua record dari tabel intrusion_data
            sql = "DELETE FROM intrusion_data;"
            cursor.execute(sql)

        # Commit perubahan ke database
        # connection.commit()

        return "Data Berhasil Dihapus!s"
    finally:
        # Tutup koneksi
        connection.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True,  use_reloader=True)

# def start_flask_app(): 
#     app.run(host='0.0.0.0', debug=True, use_reloader=False)

# scapy_thread = Thread(target=start_sniffing)
# scapy_thread.start()

# # Membuat dan memulai thread untuk Flask
# flask_thread = Thread(target=start_flask_app)
# flask_thread.start()