## Sistem Deteksi Anomali Jaringan Realtime
- Kode utama berada di folder app -> app-fix.py
- Kode dijalankan pada OS Linux Server dengan command python3 (VirtualBox 6.1 dan Python 3.10.12)
- Menggunakan dataset NSL KDD Dataset yang diperoleh dari Kaggle

## How to Install?
### Install library python yang dibutuhkan
- pandas (v2.1.0)
- flask (v2.3.3)
- pymysql (v1.1.0)
- scapy (v2.4.4)
- numpy (1.26.0)
- matplotlib (v3.8.0)
- seaborn (v0.12.2)
- scikit-learn (v1.0.2)
- scikit-optimize (v0.9.0)
- jcopml (v1.2.2)
- requests (v2.25.1)

### Jalankan Aplikasi
- Aplikasi berjalan dengan multithread
    - Thread 1 : untuk menjalankan scapy
    - Thread 2 : untuk menjalankan flask
- Command untuk menjalankan aplikasi : python3 app-fix.py
