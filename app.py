import logging
from flask import Flask, request, jsonify, render_template
import pymysql.cursors
from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, StringType, IntegerType
from scapy.all import sniff
import pickle
import json
from threading import Thread

# Initialize logging
logging.basicConfig(filename='app.log', level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)

# Set secret key
app.secret_key = b"\xa5\x90\xf6\x87\x03E\xc0#t\x05\xeb1Q\x81RH\x83'5;\xddY\xc9o"

# Initialize Spark session
spark = SparkSession.builder.appName("IntrusionDetection").getOrCreate()

# Load the trained Random Forest model
with open('rf_nsl_with_hyperparams_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Define the schema for Spark DataFrame
schema = StructType([
    StructField("duration", IntegerType(), True),
    StructField("protocol_type", StringType(), True),
    StructField("service", StringType(), True),
    StructField("src_bytes", IntegerType(), True),
    StructField("dst_bytes", IntegerType(), True)
])

# Function to process packets
def process_packet(packet):
    try:
        server_ip = "192.53.118.246"  # Replace with your server IP
        if packet.haslayer('IP') and packet['IP'].src != server_ip:
            packet_data = {
                'duration': 0,
                'protocol_type': 'tcp',
                'service': 'http',
                'src_bytes': packet['IP'].len,
                'dst_bytes': 0
            }
            logging.info(f"Processing packet: {packet_data}")  # Log added here
            
            df = spark.createDataFrame([packet_data], schema=schema)
            prediction = int(model.predict(df.toPandas())[0])
            logging.info(f"Prediction: {prediction}")  # Log added here
            
            connection = pymysql.connect(host='localhost',
                                         user='cemilick',
                                         password='Qwqwqw123',
                                         db='intrusion_detection',
                                         charset='utf8mb4',
                                         cursorclass=pymysql.cursors.DictCursor)
            
            with connection.cursor() as cursor:
                sql = "INSERT INTO `intrusion_data` (`ip_address`, `prediction`) VALUES (%s, %s)"
                cursor.execute(sql, (packet['IP'].src, prediction))
            
            connection.commit()
            connection.close()
            logging.info("Data committed to database")  # Log added here

    except Exception as e:
        logging.error(f"Error occurred while processing packet: {str(e)}")

# Function to start sniffing
def start_sniffing():
    sniff(prn=process_packet)

@app.route('/', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        df = spark.createDataFrame([data], schema=schema)
        prediction = int(model.predict(df.toPandas())[0])
        
        # Insert prediction into database
        connection = pymysql.connect(host='localhost',
                                     user='cemilick',
                                     password='Qwqwqw123',
                                     db='intrusion_detection',
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)
        
        with connection.cursor() as cursor:
            sql = "INSERT INTO `intrusion_data` (`ip_address`, `prediction`) VALUES (%s, %s)"
            cursor.execute(sql, (request.remote_addr, prediction))
        
        connection.commit()
        connection.close()

        return jsonify({'prediction': prediction})

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return jsonify({'error': str(e)})


@app.route('/getIntrusions', methods=['GET'])
def get_intrusions():
    try:
        logging.info("Fetching intrusion data")
        connection = pymysql.connect(host='localhost',
                                     user='cemilick',
                                     password='Qwqwqw123',
                                     db='intrusion_detection',
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)
        
        with connection.cursor() as cursor:
            sql = "SELECT * FROM `intrusion_data` WHERE `prediction` = 1"
            cursor.execute(sql)
            intrusions = cursor.fetchall()
        
        connection.close()
        return jsonify({'intrusions': intrusions})

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return jsonify({'error': str(e)})

@app.route('/clear')
def clearData():
    try:
        logging.info("Clearing intrusion data")
        connection = pymysql.connect(
            host='localhost',
            user='cemilick',
            password='Qwqwqw123',
            db='intrusion_detection',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )

        with connection.cursor() as cursor:
            sql = "DELETE FROM intrusion_data;"
            cursor.execute(sql)
        
        connection.commit()
        connection.close()
        return jsonify({"message": "Data cleared successfully"})

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    t = Thread(target=start_sniffing)
    t.start()
    app.run(host='0.0.0.0', port=5000, debug=True)
