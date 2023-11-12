import pandas as pd
from flask import Flask, request, jsonify, render_template
import pickle
import pymysql.cursors

# Initialize Flask app
app = Flask(__name__)

# Atur secret key
app.secret_key = b"\xa5\x90\xf6\x87\x03E\xc0#t\x05\xeb1Q\x81RH\x83'5;\xddY\xc9o"

# Load the trained Random Forest model
with open('rf_nsl_with_hyperparams_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Route for prediction
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        required_columns = ['duration', 'protocol_type', 'service', 'src_bytes', 'dst_bytes']
        
        for col in required_columns:
            if col not in data:
                return jsonify({'error': f'Missing required column: {col}'}), 400

        df = pd.DataFrame([data])
        prediction = int(model.predict(df)[0])

        connection = pymysql.connect(host='localhost',
                                     user='cemilick',
                                     password='cemilick',
                                     db='intrusion_detection',
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)
        
        with connection.cursor() as cursor:
            sql = "INSERT INTO `intrusion_data` (`ip_address`, `prediction`) VALUES (%s, %s)"
            user_ip = request.headers.get('X-Real-IP')  # Mengambil alamat IP pengguna dari header
            #cursor.execute(sql, (user_ip, prediction))
            cursor.execute(sql, (request.remote_addr, prediction))

        connection.commit()
        connection.close()

        return jsonify({'prediction': prediction})

    except Exception as e:
        return jsonify({'error': str(e)})

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
        connection.commit()
    finally:
        # Tutup koneksi
        connection.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
