# DNS Security Scanner (Python)

# Deskripsi
Program ini adalah Advanced DNS & Security Scanner berbasis CLI (Command Line Interface) menggunakan Python.
Fungsinya untuk Mengecek DNS records dari suatu domain (A, AAAA, MX, TXT, NS, CNAME, SOA), Melakukan analisis keamanan email melalui SPF, DKIM, dan DMARC,
Menampilkan ringkasan hasil di terminal, Menyimpan laporan detail dalam format JSON (dns_security_report.json).
# Cara Install
1. Pastikan sudah terinstall Python 3.x
2. Install dependency yang dibutuhkan:
   pip install dnspython
3. Clone/download repository ini, lalu masuk ke foldernya:
   git clone <url-repo>
   cd dns-security-scanner
# Cara Menggunakan
Jalankan program dengan dua opsi input:
1. Single domain:
   python dns_security_scanner.py -d example.com
2. Multiple domain (file):
   Buat file domains.txt dengan isi daftar domain (satu per baris), lalu jalankan:
   python dns_security_scanner.py -f domains.txt
# Contoh Input/Output
1. Input (domains.txt):
<img width="695" height="241" alt="image" src="https://github.com/user-attachments/assets/68d45e90-b25f-4a31-9980-aaf833c9d170" />

2. Output di Terminal:
<img width="683" height="170" alt="image" src="https://github.com/user-attachments/assets/4b9d197c-9ac3-4dd6-9ca2-235ac5d7db0e" />
<img width="683" height="179" alt="image" src="https://github.com/user-attachments/assets/192f855a-eca0-4993-a725-c2609f4c03ab" />

# Output File (dns_security_report.json)
<img width="1389" height="774" alt="image" src="https://github.com/user-attachments/assets/9c9483f1-8bb5-4b0c-95ad-91ac1f8461e0" />
<img width="1372" height="612" alt="image" src="https://github.com/user-attachments/assets/72cfba52-45a1-4444-b3b2-211094a59c2b" />
<img width="1372" height="775" alt="image" src="https://github.com/user-attachments/assets/d485b254-fa78-47f8-a095-0965b6a8cffc" />





