# Cara Build PwnFox Burp Extension

## Prasyarat

1. **Java JDK 11 atau lebih tinggi**
   - Download dari: https://adoptium.net/
   - Pastikan JAVA_HOME sudah di-set

2. **Apache Ant**
   - Download dari: https://ant.apache.org/
   - Extract dan tambahkan ke PATH
   - Atau gunakan package manager:
     - Windows (Chocolatey): `choco install ant`
     - Linux: `sudo apt-get install ant` atau `sudo yum install ant`

## Cara Build

### Menggunakan Ant

```powershell
# Build extension
ant build

# Clean dan rebuild
ant rebuild

# Hanya compile (tanpa membuat JAR)
ant compile

# Clean build directory
ant clean
```

### Output

Setelah build berhasil, file JAR akan ada di:
```
dist/PwnFox-Burp-1.0.3.jar
```

## Struktur Proyek

```
burp/
├── src/
│   └── burp/
│       └── BurpExtender.java    # Source code utama
├── build.xml                     # File konfigurasi Ant
├── build/                        # Direktori build (auto-generated)
│   └── classes/                  # File .class hasil compile
├── dist/                         # Direktori output (auto-generated)
│   └── PwnFox-Burp-1.0.3.jar    # File JAR hasil build
└── lib/                          # Direktori library (auto-generated)
    └── burp-extender-api-2.1.jar # Burp Extender API (auto-download)
```

## Instalasi di Burp Suite

1. Buka Burp Suite
2. Pergi ke tab **Extender** → **Extensions**
3. Klik **Add**
4. Pilih file `dist/PwnFox-Burp-1.0.3.jar`
5. Ekstensi akan ter-load dan menampilkan "PwnFox Loaded" di output

## Troubleshooting

### Error: 'ant' is not recognized
- Pastikan Ant sudah terinstall dan ada di PATH
- Atau gunakan full path ke ant.bat (Windows) atau ant (Linux/Mac)

### Error: JAVA_HOME not set
- Set environment variable JAVA_HOME ke direktori JDK
- Windows: `setx JAVA_HOME "C:\Program Files\Java\jdk-11"`

### Error: Cannot download Burp API
- Pastikan koneksi internet tersedia
- Atau download manual dari: https://repo1.maven.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.1/burp-extender-api-2.1.jar
- Letakkan di folder `lib/`
