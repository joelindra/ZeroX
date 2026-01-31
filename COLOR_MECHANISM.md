# Mekanisme Sistem Warna PwnFox

Dokumen ini menjelaskan bagaimana ekstensi PwnFox menghasilkan warna dan mencocokkannya antara Firefox Extension dan Burp Suite Extension.

## Alur Kerja Sistem Warna

```
Firefox Container (Warna) 
    ↓
Firefox Extension (Menambahkan Header)
    ↓
HTTP Request dengan Header X-PwnFox-Color
    ↓
Burp Proxy (Menerima Request)
    ↓
Burp Extension (Membaca Header & Highlight)
    ↓
Request ke Server (Header dihapus)
```

## 1. Firefox Extension - Menambahkan Header Warna

### Lokasi Kode: `firefox/src/features.js`

#### A. Mapping Warna Container ke Header

```javascript
// Baris 94-103: Mapping warna Firefox Container ke nilai header
const colorMap = {
    blue: "blue",           // Container biru → header "blue"
    turquoise: "cyan",      // Container turquoise → header "cyan"
    green: "green",         // Container hijau → header "green"
    yellow: "yellow",       // Container kuning → header "yellow"
    orange: "orange",       // Container orange → header "orange"
    red: "red",             // Container merah → header "red"
    pink: "pink",           // Container pink → header "pink"
    purple: "magenta",      // Container ungu → header "magenta"
}
```

**Catatan Penting:**
- Firefox menggunakan nama warna: `blue`, `turquoise`, `green`, `yellow`, `orange`, `red`, `pink`, `purple`
- Header menggunakan nilai: `blue`, `cyan`, `green`, `yellow`, `orange`, `red`, `pink`, `magenta`
- Perbedaan: `turquoise` → `cyan`, `purple` → `magenta`

#### B. Fungsi `colorHeaderHandler` (Baris 91-115)

```javascript
async function colorHeaderHandler(e) {
    if (e.tabId < 0) return  // Skip jika bukan request dari tab
    
    // Mapping warna container ke nilai header
    const colorMap = { ... }
    
    // Ambil informasi tab dan container
    const { cookieStoreId } = await browser.tabs.get(e.tabId)
    
    // Skip jika menggunakan default container (tanpa warna)
    if (cookieStoreId === "firefox-default") {
        return {}
    }
    
    // Ambil informasi container (identity)
    const identity = await browser.contextualIdentities.get(cookieStoreId)
    
    // Hanya tambahkan header jika container dimulai dengan "PwnFox-"
    if (identity.name.startsWith("PwnFox-")) {
        const name = "X-PwnFox-Color"           // Nama header
        const value = colorMap[identity.color]   // Nilai warna dari mapping
        e.requestHeaders.push({ name, value })   // Tambahkan header
    }
    
    return { requestHeaders: e.requestHeaders }
}
```

**Cara Kerja:**
1. Extension mendengarkan event `webRequest.onBeforeSendHeaders`
2. Ketika request akan dikirim, handler dipanggil
3. Mengecek apakah tab menggunakan Firefox Container (bukan default)
4. Mengecek apakah container dimulai dengan nama "PwnFox-"
5. Mengambil warna container dan mapping ke nilai header
6. Menambahkan header `X-PwnFox-Color: <warna>` ke request

#### C. Class `AddContainerHeader` (Baris 117-136)

```javascript
class AddContainerHeader extends Feature {
    constructor(config) {
        super(config, 'addContainerHeader')  // Feature name di config
    }

    async start() {
        super.start()
        if (!await this.config.get("enabled")) return

        // Register listener untuk menambahkan header
        browser.webRequest.onBeforeSendHeaders.addListener(
            colorHeaderHandler,
            { urls: ["<all_urls>"] },        // Semua URL
            ["blocking", "requestHeaders"]    // Blocking mode, akses requestHeaders
        );
    }

    stop() {
        browser.webRequest.onBeforeSendHeaders.removeListener(colorHeaderHandler)
        super.stop()
    }
}
```

## 2. Burp Extension - Membaca Header dan Highlight

### Lokasi Kode: `burp/src/burp/BurpExtender.java`

#### A. Interface yang Diimplementasikan

```java
public class BurpExtender implements 
    IBurpExtender,           // Interface utama ekstensi
    IProxyListener,          // Mendengarkan proxy messages
    IExtensionStateListener  // Mendengarkan state ekstensi
```

#### B. Registrasi Proxy Listener (Baris 15-26)

```java
@Override
public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    this.helpers = callbacks.getHelpers();
    
    callbacks.setExtensionName("PwnFox");
    callbacks.registerExtensionStateListener(this);
    callbacks.registerProxyListener(this);  // ← Register untuk mendengarkan proxy
    stdout.println("PwnFox Loaded");
}
```

#### C. Fungsi `processProxyMessage` (Baris 33-65)

```java
@Override
public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
    // Hanya proses request (bukan response)
    if (!messageIsRequest) return;

    IHttpRequestResponse messageInfo = message.getMessageInfo();
    if (messageInfo != null) {
        
        // 1. Parse request untuk mendapatkan headers
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        
        // 2. Extract body dari request
        byte[] body = new byte[messageInfo.getRequest().length - requestInfo.getBodyOffset()];
        System.arraycopy(messageInfo.getRequest(), requestInfo.getBodyOffset(), body, 0, body.length);
        
        // 3. Pisahkan headers menjadi dua kategori:
        //    - pwnFoxHeaders: header yang dimulai dengan "x-pwnfox-"
        //    - cleanHeaders: header lainnya
        List<String> headers = requestInfo.getHeaders();
        List<String> pwnFoxHeaders = new ArrayList<>();
        List<String> cleanHeaders = new ArrayList<>();
        
        for (String header : headers) {
            if (header.toLowerCase(Locale.getDefault()).startsWith("x-pwnfox-")) {
                pwnFoxHeaders.add(header);  // Header PwnFox (akan dihapus)
            } else {
                cleanHeaders.add(header);   // Header normal (akan dikirim)
            }
        }

        // 4. Cari header X-PwnFox-Color dan set highlight
        for (String header : pwnFoxHeaders) {
            if (header.toLowerCase(Locale.getDefault()).startsWith("x-pwnfox-color:")) {
                String[] parts = header.split(":", 2);
                if (parts.length == 2) {
                    // Set highlight di Burp dengan warna dari header
                    messageInfo.setHighlight(parts[1].trim());
                }
            }
        }
        
        // 5. Rebuild request tanpa header PwnFox (header dihapus sebelum dikirim ke server)
        messageInfo.setRequest(helpers.buildHttpMessage(cleanHeaders, body));
    }
}
```

**Cara Kerja:**
1. Extension mendengarkan semua proxy messages
2. Hanya memproses request (bukan response)
3. Parse request untuk mendapatkan headers
4. Pisahkan header menjadi:
   - `pwnFoxHeaders`: header yang dimulai dengan `x-pwnfox-` (akan dihapus)
   - `cleanHeaders`: header normal (akan dikirim ke server)
5. Cari header `X-PwnFox-Color: <warna>`
6. Set highlight di Burp dengan warna tersebut menggunakan `messageInfo.setHighlight()`
7. Rebuild request tanpa header PwnFox (header dihapus sebelum dikirim)

## 3. Mapping Warna Lengkap

| Firefox Container | Header Value | Burp Highlight |
|-------------------|--------------|----------------|
| `blue`            | `blue`       | blue           |
| `turquoise`       | `cyan`       | cyan           |
| `green`           | `green`      | green          |
| `yellow`          | `yellow`     | yellow         |
| `orange`          | `orange`     | orange         |
| `red`             | `red`        | red            |
| `pink`            | `pink`       | pink           |
| `purple`          | `magenta`    | magenta        |

## 4. Contoh Request Flow

### Request dari Firefox Container "PwnFox-blue":

```
1. Firefox Extension menambahkan header:
   X-PwnFox-Color: blue

2. Request dikirim ke Burp Proxy:
   GET /api/data HTTP/1.1
   Host: example.com
   X-PwnFox-Color: blue
   User-Agent: Mozilla/5.0...

3. Burp Extension memproses:
   - Membaca header X-PwnFox-Color: blue
   - Set highlight = "blue" di Burp
   - Hapus header X-PwnFox-Color

4. Request dikirim ke server (tanpa header PwnFox):
   GET /api/data HTTP/1.1
   Host: example.com
   User-Agent: Mozilla/5.0...
```

## 5. Konfigurasi

### Firefox Extension
- Feature: `addContainerHeader` (default: `true`)
- Dapat diaktifkan/nonaktifkan di popup extension

### Burp Extension
- Otomatis aktif setelah di-load
- Tidak ada konfigurasi tambahan

## 6. Keuntungan Sistem Ini

1. **Visual Identification**: Request dari container berbeda langsung terlihat di Burp
2. **Non-Invasive**: Header dihapus sebelum dikirim ke server, tidak mengubah behavior aplikasi
3. **Automatic**: Tidak perlu konfigurasi manual, warna otomatis sesuai container
4. **Flexible**: Bisa membuat container baru dengan warna berbeda untuk identitas berbeda

## 7. Troubleshooting

### Warna tidak muncul di Burp:
1. Pastikan feature `addContainerHeader` aktif di Firefox extension
2. Pastikan container dimulai dengan nama "PwnFox-"
3. Pastikan Burp extension sudah ter-load
4. Pastikan request melalui Burp proxy

### Header tidak dihapus:
- Check log Burp extension untuk error
- Pastikan kode di `processProxyMessage` berjalan dengan benar
