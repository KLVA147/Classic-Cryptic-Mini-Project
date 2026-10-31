# Classic Cryptic

**Classic Cryptic** adalah website interaktif berbasis web yang dirancang untuk melatih pemahaman tentang kriptografi klasik. Pengguna dapat mencoba berbagai algoritma cipher, mengenkripsi maupun mendekripsi pesan secara real-time, serta mempelajari cara kerja tiap algoritma melalui visualisasi langkah demi langkah.

---

## Tujuan Pembangunan

Website ini dibangun dengan tiga tujuan utama:

1. **Edukasi** — Membantu pemula memahami konsep dasar kriptografi klasik secara visual dan interaktif, bukan hanya teori.
2. **Eksplorasi** — Menyediakan ruang uji coba yang mudah diakses untuk berbagai algoritma cipher klasik tanpa perlu instalasi apapun.
3. **Pelatihan pola (pattern training)** — Melatih kemampuan analisis ciphertext melalui alat bantu kriptanalisis seperti analisis frekuensi, Index of Coincidence, dan deteksi pola kata.

---

## Struktur File

```
classic-cryptic/
├── index.html    — Struktur tampilan (HTML)
├── style.css     — Semua styling dan design tokens
├── process.js    — Seluruh logika algoritma dan interaksi
└── README.md     — Dokumentasi ini
```

---

## Fitur-Fitur

### 1. 8 Algoritma Cipher Klasik

| Algoritma | Tipe | Kunci |
|---|---|---|
| **Caesar** | Substitusi | Slider geser (1–25) |
| **Rail Fence** | Transposisi | Slider jumlah rel (2–8) |
| **Vigenère** | Polialfabetik | Input kata kunci |
| **Monoalphabetic** | Substitusi | Tabel peta 26 huruf |
| **Playfair** | Substitusi digraf | Kata kunci + preview kisi 5×5 |
| **Hill** | Matriks | Input matriks 2×2 atau 3×3 |
| **Scytale** | Transposisi | Slider jumlah baris (2–10) |
| **Columnar** | Transposisi | Input kata kunci + preview urutan kolom |

---

### 2. Workspace Split-Screen

- Dua panel teks (input & output) bersebelahan
- Proses enkripsi/dekripsi berjalan **real-time** saat mengetik
- Tombol bulat di tengah untuk **toggle mode** Encrypt ↔ Decrypt
- Tombol pendukung: **Clear**, **Sample** (contoh teks), **Copy output**, **Swap** (pindah output ke input)

---

### 3. Dynamic Key Controller

Panel kunci yang menyesuaikan tampilannya secara otomatis berdasarkan algoritma yang dipilih:

- **Slider angka** untuk Caesar dan Scytale
- **Input kata kunci** untuk Vigenère, Playfair, dan Columnar
- **Grid input matriks** untuk Hill (pilihan ukuran 2×2 atau 3×3)
- **Tabel substitusi 26 sel** yang bisa diedit langsung untuk Monoalphabetic
- **Preview kisi 5×5** yang diperbarui otomatis untuk Playfair
- **Preview urutan kolom** berdasarkan alfabet kunci untuk Columnar

---

### 4. Visualisasi Step-by-Step

Setiap algoritma memiliki visualisasi animasi tersendiri yang menampilkan cara kerjanya secara bertahap:

| Algoritma | Bentuk Visualisasi |
|---|---|
| **Caesar** | Dua cincin alfabet SVG yang berputar |
| **Rail Fence** | Grid zigzag dengan highlight per karakter |
| **Vigenère** | Tabel plain–kunci–hasil per posisi |
| **Monoalphabetic** | Peta substitusi + pasangan karakter |
| **Playfair** | Kisi 5×5 dengan highlight sel sumber & tujuan |
| **Hill** | Tampilan matriks × vektor = hasil per blok |
| **Scytale** | Grid kolom dengan highlight kolom aktif |
| **Columnar** | Tabel grid dengan header kunci + urutan baca |

Navigasi langkah menggunakan tombol **Prev / Next** atau mode **Auto-play** (interval 900ms).

---

### 5. Cryptanalysis Helper

Panel alat bantu untuk pemula dalam menganalisis ciphertext, terbagi tiga tab:

- **Frequency Analysis** — Grafik batang frekuensi 26 huruf dari output, dibandingkan dengan rata-rata bahasa Inggris
- **Index of Coincidence (IoC)** — Nilai IoC dengan interpretasi otomatis (acak / polialfabetik / monoalfabetik / plaintext)
- **Word Pattern Detector** — Setiap kata dipetakan ke pola strukturalnya (contoh: `HELLO → 0.1.2.2.3`) beserta saran kata Inggris yang cocok

---

### 6. Tampilan Futuristik & Responsif

- Palet warna pastel lembut: kuning `#fde68a`, pink `#fbcfe8`, biru muda `#bfdbfe`, ungu `#ddd6fe`
- Background grid animasi, header glassmorphism dengan `backdrop-filter: blur`
- Card dengan rounded corner, soft shadow, dan hover lift effect
- Layout dua kolom di desktop (sidebar kiri + konten kanan)
- **Mobile-first responsive** — kolom collapse ke satu pada layar ≤ 1024px

---

## Cara Menjalankan

Tidak perlu instalasi atau build process. Cukup buka file langsung di browser:

```
classic-cryptic/index.html
```

> Karena menggunakan `<script src="process.js">`, file harus dibuka melalui server lokal (misalnya Live Server di VS Code) atau langsung dari filesystem di browser yang mendukung.

---

## Teknologi

- **HTML5** — Struktur semantik
- **CSS3** — Custom properties (design tokens), CSS Grid, animasi, media queries
- **Vanilla JavaScript (ES6+)** — Tanpa framework atau library eksternal

---

## Referensi Algoritma

- **Caesar** — *Julius Caesar, 58 SM*
- **Rail Fence** — Cipher transposisi zigzag
- **Vigenère** — *Blaise de Vigenère, 1553*
- **Playfair** — *Charles Wheatstone, 1854; dipopulerkan Lord Playfair*
- **Hill** — *Lester S. Hill, 1929*
- **Scytale** — *Sparta kuno, ~700 SM*
- **Columnar** — Varian transposisi dengan kunci kata
