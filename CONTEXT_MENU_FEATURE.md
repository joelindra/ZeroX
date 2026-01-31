# Fitur Context Menu - PwnFox Burp Extension

## Deskripsi

Fitur ini memungkinkan user untuk mengganti `Authorization: Bearer` header dari request saat ini dengan `Authorization: Bearer` dari request lain yang memiliki warna tertentu melalui context menu di Burp Suite.

## Cara Menggunakan

### Langkah-langkah:

1. **Pastikan request memiliki Authorization header**
   - Request yang akan dimodifikasi harus memiliki header `Authorization: Bearer`

2. **Klik kanan pada request**
   - Di Proxy History, Repeater, atau Intruder
   - Klik kanan pada request yang ingin dimodifikasi

3. **Pilih menu PwnFox > Select Color**
   - Menu akan muncul dengan pilihan warna:
     - blue
     - cyan
     - green
     - yellow
     - orange
     - red
     - pink
     - magenta

4. **Pilih warna yang diinginkan**
   - Extension akan mencari request terbaru dengan warna tersebut yang memiliki Authorization header
   - Authorization header dari request saat ini akan diganti dengan Authorization header dari request dengan warna yang dipilih

### Contoh Skenario:

```
1. User memiliki request A dengan warna blue yang memiliki:
   Authorization: Bearer token-blue-123

2. User memiliki request B dengan warna pink yang memiliki:
   Authorization: Bearer token-pink-456

3. User membuka request A di Repeater
4. User klik kanan > PwnFox > Select Color > pink
5. Request A sekarang memiliki:
   Authorization: Bearer token-pink-456
```

## Implementasi Teknis

### 1. Context Menu Factory

Extension mengimplementasikan `IContextMenuFactory` untuk menambahkan menu:

```java
@Override
public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    // Membuat menu "PwnFox > Select Color > [warna]"
}
```

**Menu muncul di:**
- Proxy History
- Message Editor (Request)
- Message Viewer (Request)
- Intruder Payload Positions

### 2. Request History Storage

Extension menyimpan history request berdasarkan warna:

```java
private Map<String, List<IHttpRequestResponse>> requestHistoryByColor;
```

**Cara penyimpanan:**
- Setiap request yang melalui proxy dengan warna tertentu disimpan
- Maksimal 100 request per warna (untuk menghindari masalah memory)
- History disimpan dari `processProxyMessage` dan `processHttpMessage`

### 3. Pencarian Authorization Header

Extension mencari Authorization header dengan urutan:

1. **Dari stored history** (memory)
   - Mencari dari request terbaru ke terlama
   - Hanya mencari request dengan warna yang dipilih

2. **Dari Proxy History** (jika tidak ditemukan di memory)
   - Mencari dari seluruh Proxy History
   - Filter berdasarkan warna yang dipilih
   - Mencari dari request terbaru ke terlama

### 4. Penggantian Header

```java
private void replaceAuthorizationHeader(IHttpRequestResponse currentRequest, String targetColor) {
    // 1. Cari Authorization header di request saat ini
    // 2. Cari Authorization header dari request dengan warna target
    // 3. Ganti Authorization header
    // 4. Rebuild request dengan header baru
}
```

**Proses:**
1. Parse request saat ini untuk mendapatkan headers
2. Identifikasi Authorization header yang akan diganti
3. Cari Authorization header dari request dengan warna target
4. Ganti Authorization header di request saat ini
5. Rebuild request dengan headers baru
6. Update request menggunakan `setRequest()`

## Mapping Warna

Warna yang tersedia sesuai dengan mapping di Firefox extension:

| Firefox Container | Header Value | Menu Option |
|------------------|--------------|-------------|
| blue             | blue         | blue        |
| turquoise        | cyan         | cyan        |
| green            | green        | green       |
| yellow           | yellow       | yellow      |
| orange           | orange       | orange      |
| red              | red          | red         |
| pink             | pink         | pink        |
| purple           | magenta      | magenta     |

## Logging

Extension mencatat aktivitas di Burp output:

**Success:**
```
[PwnFox] Authorization header replaced from color: pink
[PwnFox] Old: Authorization: Bearer token-blue-123
[PwnFox] New: Authorization: Bearer token-pink-456
```

**Error:**
```
[PwnFox] No Authorization header found in current request
[PwnFox] No request found with color: pink
[PwnFox] No Authorization header found in requests with color: pink
```

## Batasan

1. **Request harus memiliki Authorization header**
   - Jika request tidak memiliki Authorization header, operasi akan dibatalkan

2. **Harus ada request dengan warna target**
   - Jika tidak ada request dengan warna yang dipilih, operasi akan dibatalkan

3. **Request dengan warna target harus memiliki Authorization header**
   - Jika request dengan warna target tidak memiliki Authorization header, operasi akan dibatalkan

4. **History terbatas**
   - Hanya 100 request terakhir per warna yang disimpan di memory
   - Jika request tidak ada di memory, akan dicari di Proxy History

## Troubleshooting

### Menu tidak muncul:
- Pastikan ekstensi sudah ter-load
- Pastikan klik kanan di context yang benar (Proxy History, Repeater, dll)
- Pastikan ada request yang dipilih

### "No Authorization header found":
- Pastikan request memiliki header `Authorization: Bearer`
- Header harus dimulai dengan "authorization:" (case-insensitive)

### "No request found with color":
- Pastikan ada request yang pernah melalui proxy dengan warna tersebut
- Pastikan request tersebut sudah tersimpan di Proxy History

### Header tidak terganti:
- Check output di Burp untuk error messages
- Pastikan request yang dipilih bisa dimodifikasi (bukan read-only)

## Use Cases

1. **Testing dengan Multiple Users**
   - Setiap user menggunakan container berbeda (warna berbeda)
   - Dengan cepat switch Authorization token antar user

2. **Token Rotation Testing**
   - Test dengan token dari berbagai session
   - Cepat mengganti token tanpa copy-paste manual

3. **Multi-Account Testing**
   - Test dengan akun berbeda yang memiliki token berbeda
   - Visual identification melalui warna container
