from flask import Flask, render_template, json
import pyshark

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def packet_callback(pkt):
    print(pkt)

@app.route('/start_capture')
def start_capture():
    cap = pyshark.LiveCapture(interface='enp0s3')
    result = []
    for packet in cap.sniff_continuously(packet_count=5):
        result.append(json.dumps(packet))
    
    return result

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
