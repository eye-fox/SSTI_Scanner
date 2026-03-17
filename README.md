# SSTI Scanner

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/ssti-scanner/graphs/commit-activity)

**SSTI Scanner** adalah alat keamanan siber (offensive security tool) yang dirancang untuk mendeteksi kerentanan **Server-Side Template Injection (SSTI)** secara otomatis pada aplikasi web. Alat ini mampu mengidentifikasi titik injeksi, melakukan fingerprinting terhadap mesin template yang digunakan, serta mengkonfirmasi kerentanan dengan serangkaian payload yang telah diverifikasi.

## 🚀 Fitur Utama

*   **Deteksi Otomatis**: Menemukan parameter GET/POST yang berpotensi menjadi titik injeksi SSTI.
*   **Engine Fingerprinting**: Mengidentifikasi mesin template yang digunakan (seperti Jinja2, Twig, Freemarker, dll.) berdasarkan pola kesalahan dan tanda tangan unik dalam respons server.
*   **Multi-Platform Scanning**: Mendukung pemindaian pada aplikasi yang dibangun dengan berbagai bahasa pemrograman dan framework (Python, PHP, Java, JavaScript, Ruby, Go, .NET, dan lainnya).
*   **Konfirmasi Kerentanan (Verification)**: Melakukan verifikasi lanjutan dengan payload aritmatika (misal: `{{7*7}}` dieksekusi menjadi `49`) untuk mengurangi positif palsu.
*   **Analisis Respons Cerdas**: Menganalisis kode status HTTP, panjang konten, pesan error, stack trace, dan konteks refleksi payload.
*   **Manajemen Sesi**: Mendukung penggunaan cookie untuk pemindaian pada area yang memerlukan autentikasi.
*   **Pemindaian Konkuren**: Mampu memindai banyak URL secara bersamaan (asinkron) untuk efisiensi waktu.
*   **Daftar URL Massal**: Mendukung pemindaian dari file daftar target.
*   **Output Terstruktur**: Menyimpan hasil temuan ke dalam file teks biasa yang mudah dibaca.
*   **Evasion Sederhana**: Menggunakan User-Agent, Header, dan Cipher Suites acak untuk menghindari deteksi sederhana.

## 🛠️ Instalasi

1.  **Clone repositori ini:**
    ```bash
    git clone https://github.com/eye-fox/SSTI_Scanner.git
    cd ssti-scanner
    ```

2.  **Instal dependensi yang diperlukan:**
    Alat ini membutuhkan Python 3.7 atau lebih baru. Disarankan untuk menggunakan lingkungan virtual.
    ```bash
    pip install -r requirements.txt
    ```
    *Catatan: Jika belum memiliki file `requirements.txt`, Anda dapat menginstal pustaka yang diperlukan secara manual:*
    ```bash
    pip install requests beautifulsoup4 aiohttp urllib3
    ```

## 📖 Cara Penggunaan

### Dasar (Single URL)
```bash
python ssti_scanner.py -u "http://target.com/page?name=test"
```

Dengan Cookie (untuk area login)

```bash
python ssti_scanner.py -u "http://target.com/dashboard" -c "sessionid=abc123; csrftoken=xyz456"
```

Memindai Banyak URL dari File

Buat file teks (misal: targets.txt) yang berisi daftar URL, satu per baris.

```
http://example.com/page1
http://example.com/page2?q=query
https://testsite.org/form
```

Kemudian jalankan:

```bash
python ssti_scanner.py -l targets.txt -t 10
```

Parameter -t mengatur jumlah koneksi konkuren (default: 5).

Menyimpan Hasil ke File

```bash
python ssti_scanner.py -u "http://target.com/page" -o hasil_scan.txt
```

Argumen Lengkap

Argumen Pendek Argumen Panjang Deskripsi
-u --url URL target tunggal untuk dipindai.
-l --list File yang berisi daftar URL target.
-c --cookie String cookie untuk permintaan yang diautentikasi.
-o --output File output untuk menyimpan hasil temuan.
-t --threads Jumlah maksimum koneksi konkuren (default: 5).

📊 Contoh Output

Ketika Kerentanan Ditemukan (Confirmed)

```
[!!!] CRITICAL: SSTI DETECTED
    → URL: http://target.com/welcome
    → Method: GET
    → Parameter: name
    → Verified payloads: 1
    → {{7*7}}
```

Potensi Kerentanan (Unverified)

```
[!] POTENTIAL SSTI
    → URL: http://target.com/search
    → Method: POST
    → Parameter: query
    → Unverified payloads: 2
    → ${7*7}
    → {{7*7}}
```

Deteksi Engine dari Error Payload

```
[!!!] CRITICAL: SSTI DETECTED
    → URL: http://target.com/profile
    → Method: POST
    → Parameter: bio
    → Engine(s): jinja2
    → Affected payloads: 3 payloads
    → Examples: {{config}}, {{7*7}}, {{self.__class__}}
```

Anomali / Indikasi Kuat

```
[!] HIGH SEVERITY ANOMALIES
    → URL: http://target.com/page
    → Method: GET
    → Parameter: id
    → ${{<%[%'"}}%\: stack_trace_detected
```

🧠 Cara Kerja

1. Ekstraksi Parameter: Memuat halaman target dan mengekstrak semua parameter dari URL (GET) dan formulir HTML (POST).
2. Pemetaan Titik Refleksi (Probing): Mengirimkan string unik (misal: SSTI_PROBE_1_12345) ke setiap parameter untuk melihat apakah dan di mana string tersebut direfleksikan kembali oleh server.
3. Analisis Baseline: Membandingkan respons dari probe dengan respons normal untuk mendeteksi perubahan perilaku server.
4. Pengiriman Payload: Mengirimkan serangkaian payload SSTI umum ke titik injeksi yang teridentifikasi.
5. Verifikasi dan Analisis:
   · Mencari refleksi hasil eksekusi aritmatika (49, 25).
   · Menganalisis pesan error, stack trace, dan kode status HTTP (terutama 500).
   · Melakukan fingerprinting mesin template berdasarkan teks error dan tanda tangan yang ada di basis data (data_ssti.py).
6. Pelaporan: Menampilkan hasil temuan di konsol dan menyimpannya ke file output dengan tingkat keparahan (CRITICAL, HIGH, MEDIUM, POTENTIAL).

🤝 Kontribusi

Kontribusi selalu diterima dengan tangan terbuka! Jika Anda ingin berkontribusi pada proyek ini, silakan lakukan langkah-langkah berikut:

1. Fork repositori ini.
2. Buat branch fitur baru (git checkout -b fitur-keren-anda).
3. Commit perubahan Anda (git commit -m 'Menambahkan fitur deteksi engine baru').
4. Push ke branch (git push origin fitur-keren-anda).
5. Buat Pull Request baru.

⚠️ Penafian

Alat ini dibuat untuk tujuan pengujian keamanan dan pendidikan semata. Penggunaan alat ini pada sistem atau aplikasi web tanpa izin tertulis dari pemilik adalah ilegal. Pengembang tidak bertanggung jawab atas segala penyalahgunaan atau kerusakan yang disebabkan oleh alat ini. Selalu patuhi hukum dan regulasi yang berlaku.

📄 Lisensi

Proyek ini dilisensikan di bawah Lisensi MIT. Lihat file LICENSE untuk informasi lebih lanjut.

---

Dibuat dengan ❤️ untuk keamanan siber.
