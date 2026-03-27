# 🛡️ ZeroX v1.2.0

> **Advanced IDOR & BAC Automation Tool for Burp Suite**

[![Release](https://img.shields.io/badge/Release-v1.2.0-blue.svg)](https://github.com/joelindra/ZeroX/releases)
[![Build](https://img.shields.io/badge/Build-Maven-orange.svg)](https://maven.apache.org/)
[![Java](https://img.shields.io/badge/Java-11%2B-red.svg)](https://www.oracle.com/java/)
[![Firefox Extension](https://img.shields.io/badge/Firefox-Plugin-purple.svg)](https://addons.mozilla.org/en-US/firefox/addon/zerox/)

**ZeroX** is a high-performance Burp Suite extension meticulously engineered to streamline the identification of **Insecure Direct Object Reference (IDOR)** and **Broken Access Control (BAC)** vulnerabilities. By combining real-time automation with a sophisticated user interface, ZeroX enables security researchers to perform deep authorization analysis with surgical precision.

---

## 📽️ Preview

<img width="1679" height="1247" alt="image" src="https://github.com/user-attachments/assets/8d29b2a1-c4bc-42b5-abc7-c719e355109b" />

---

## ✨ Key Features

### 🎨 Intelligent Highlighting

Automatically synchronizes Burp Suite highlight colors with **Firefox Containers**. Instantly categorize traffic from different user sessions (e.g., Admin, Regular User, Guest) visually using the `x-zerox-Color` header.

### ⚡ Automated Batch Testing

Perform massive IDOR scans across multiple requests. ZeroX compares original responses with modified ones, highlighting anomalies in status codes and body lengths automatically in a clear results table.

### ⏲️ Real-Time Authorization Analysis

Intercept and re-test requests on-the-fly. ZeroX duplicates live traffic, injects alternative authorization headers, and identifies potential bypasses without manual intervention as you browse.

### 📊 Professional Data Viewer

Deep integration with Burp Suite's native message editors. Compare original and modified request/response pairs with full syntax highlighting and standard Burp inspection tools.

### 🔍 Precision Filtering

Eliminate background noise. Use advanced domain filtering to focus your real-time testing on specific target applications, ensuring zero interference from third-party services or analytics.

---

## 🛠️ Getting Started

### Prerequisites

- **Java JDK 11** or higher
- **Apache Maven**
- **Burp Suite Professional/Community**

### Building from Source

1. Clone the repository.
2. Navigate to the project directory.
3. Execute the build command:

```powershell
mvn clean package
```

4. Find the compiled result at `target/zero-x-1.2.0.jar`.

### Installation

1. Open Burp Suite.
2. Navigate to the **Extensions** tab.
3. Click **Add** and select **Extension type: Java**.
4. Browse to `target/zero-x-1.2.0.jar` and click **Next**.

---

## 📖 Deep Dive: Usage Guide

### 1. The Firefox Bridge

ZeroX pairs perfectly with the **[ZeroX Firefox Plugin](https://addons.mozilla.org/en-US/firefox/addon/zerox/)**.

- It detects the `x-zerox-Color` header injected by the plugin.
- Simply name your containers starting with `zerox-` (e.g., `zerox-admin`, `zerox-user`).

### 2. Automate BAC Workflow

1. Collect requests in the **Automate BAC** tab.
2. Provide the target authorization token (Bearer, Cookie, etc.).
3. Hit **Start Test**.
4. Analyze the results for status differences or size deviations.

### 3. Real-Time Guardian

1. Toggle **Real Time BAC** to ON.
2. Input your secondary user's authorization header.
3. Set the **Domain Filter** (use "Select" for focused testing).
4. Browse the application naturally; ZeroX will report findings in the results panel.

---

## 📁 Project Architecture

```text
burp/
├── 📂 assets/          # Brand assets and visual documentation
├── 📂 src/             # Core Java source code
│   └── 📂 main/java    # Managed under Maven standards
├── 📄 pom.xml          # Maven Project Object Model
└── 📄 BUILD.md         # Detailed build instructions
```

---

## 🛡️ Disclaimer

This software is provided for **educational and ethical security testing** purposes only. The author assumes no liability for damages or legal issues resulting from improper use. Always obtain explicit written permission before testing any target.

---

## 🤝 Contribution & Support

Contributions drive the evolution of ZeroX. Feel free to:

- Open an **Issue** for bug reports or feature requests.
- Submit a **Pull Request** to improve the codebase.
- Star the repository if you find it useful for your research!

---

Developed with ❤️ for the Security Community
