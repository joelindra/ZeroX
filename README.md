# ZeroX - Advanced IDOR & BAC Automation Tool for Burp Suite
## Link to Firefox Plugin: https://addons.mozilla.org/en-US/firefox/addon/zerox/
**ZeroX** is a specialized Burp Suite extension designed to accelerate the testing process for **IDOR (Insecure Direct Object Reference)** and **BAC (Broken Access Control)** vulnerabilities. With its modern interface and intelligent automation, ZeroX empowers security researchers to identify authorization flaws with unprecedented efficiency.

---

## 🚀 Key Features

- **🎨 Color-Synced Highlighting**: Automatically synchronizes Burp Suite highlight colors based on the Firefox Container being used. Visually distinguish requests from different users in an instant.
- **⚡ Automated BAC Tester**: Perform batch IDOR testing on a collection of requests. Effortlessly compare original responses with modified ones using different authorization tokens.
- **⏲️ Real-Time BAC Testing**: Intercept and test requests in real-time as you browse. ZeroX automatically duplicates requests and attempts them with your pre-configured Authorization headers.
- **📊 Interactive Comparison**: Features an intuitive request/response comparison viewer to help you analyze differences in status codes, body lengths, and response content.
- **🔍 Smart Filtering**: Filter target domains for real-time testing to eliminate noise from external analytics or third-party services.
- **✨ Modern UI/UX**: A refined Swing-based interface with a contemporary design (Glassmorphism inspired, pill buttons, and a clean light theme).

---

## 🛠️ Prerequisites

Before building the tool, ensure you have the following installed:

1. **Java JDK 11** or higher.
2. **Apache Ant** (for the build process).

---

## 🏗️ Build & Installation

### 1. Build from Source

Use Apache Ant to compile and package the extension into a JAR file:

```powershell
# Run in the project directory
ant build
```

The resulting `.jar` file will be available in the `dist/` directory.

### 2. Installation in Burp Suite

1. Open **Burp Suite**.
2. Navigate to the **Extensions** tab.
3. Click the **Add** button.
4. Select **Extension type: Java**.
5. Select the JAR file located at `dist/ZeroX-Burp-1.0.0.jar`.
6. The **ZeroX** tab will appear in Burp Suite's main dashboard.

---

## 📖 How to Use

### 1. Color Synchronization (Container Highlighting)

ZeroX works by reading the `x-zerox-Color` header sent by the Firefox extension.

- Use Firefox Containers with the name prefix `zerox-`.
- Incoming requests to Burp will be automatically highlighted with the color matching the container.

### 2. Automated IDOR Testing (Automate BAC)

1. Collect the requests you want to test in the **Automate BAC** tab.
2. Input the target authorization token (e.g., a Bearer Token or Cookie from another user).
3. Click **Start Test**.
4. ZeroX will process all requests and display a comparison of statuses and response sizes.

### 3. Real-Time Testing (Real-Time BAC)

1. Enable the **Real Time BAC** toggle.
2. Configure the **Authorization Header** you wish to use for testing (e.g., from a low-level user or a different account).
3. Set the **Domain Filter** to focus only on the application under test.
4. As you browse, ZeroX will duplicate each request with the new header and report findings if a potential bypass is detected.

---

## 📁 Project Structure

```text
burp/
├── src/
│   └── burp/
│       └── BurpExtender.java    # Core extension logic
├── assets/                       # Images & documentation assets
├── build.xml                     # Apache Ant configuration
├── lib/                          # Library dependencies
└── dist/                         # Compiled output (.jar)
```

---

## 🛡️ Security & Disclaimer

This tool is intended for **security research** and **bug bounty hunting** purposes only. Using this tool against targets without explicit written permission is illegal. The author is not responsible for any misuse of this tool.

---

## 🤝 Contribution

Contributions are always welcome! Feel free to fork this repository and submit a Pull Request if you have ideas for new features or bug fixes.

---


