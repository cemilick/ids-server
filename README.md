## Sistem Deteksi Anomali Jaringan Realtime
- Kode utama berada di folder app -> app-fix.py
- Kode dijalankan pada OS Linux Server dengan command python3
- Menggunakan dataset NSL KDD Dataset yang diperoleh dari Kaggle

## How to Install?
### Install library python yang dibutuhkan
- pandas
- flask
- pickle
- pymysql.cursors
- scapy
- threading
- numpy
- matplotlib
- seaborn
- sklearn
- jcopml

### Jalankan Aplikasi
- Aplikasi berjalan dengan multithread
    - Thread 1 : untuk menjalankan scapy
    - Thread 2 : untuk menjalankan flask
- Command untuk menjalankan aplikasi : python3 app-fix.py
