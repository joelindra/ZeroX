# 🛡️ ZeroX v2.0.0

> **Advanced Browser Container Highlight, Session Bridge & Auth Matrix for Burp Suite (Montoya API)**

[![Release](https://img.shields.io/badge/Release-v2.0.0-blue.svg)](https://github.com/joelindra/ZeroX/releases)
[![Build](https://img.shields.io/badge/Build-Maven-orange.svg)](https://maven.apache.org/)
[![Java](https://img.shields.io/badge/Java-11%2B-red.svg)](https://www.oracle.com/java/)
[![Firefox Extension](https://img.shields.io/badge/Firefox-Plugin-purple.svg)](https://addons.mozilla.org/en-US/firefox/addon/zerox/)

<img width="1768" height="1348" alt="image" src="https://github.com/user-attachments/assets/e281b4b9-a017-4b37-9898-982e4671aa83" />

**ZeroX** is a high-performance Burp Suite extension engineered to bridge the gap between browser containers and Burp Suite's highlighting/repeater workflows. By syncing Firefox Container colors with Burp's request highlights, it allows security researchers to manage and swap authorization sessions seamlessly without the need for additional UI panels.

**New in v2.0**: Fully migrated to **Portswigger Montoya API** with Auto-Pilot Session Sync and Instant Privilege Escalation (Auth Matrix) Generator.

---

## ✨ Key Features

### 🎨 Intelligent Highlighting

Automatically synchronizes Burp Suite highlight colors with **Firefox Containers**. Instantly categorize traffic from different user sessions (e.g., Admin, Regular User, Guest) visually using the `x-zerox-color` header injected by our Firefox plugin.

### 🔑 Session Auth Bridge (Select Auth)

Quickly swap authorization tokens across sessions. Right-click any HTTP request in Burp, select **ZeroX** -> **Select Auth**, and pick a container color to automatically replace the `Authorization` header with the latest cached token from that container.

### 🚀 Auto-Pilot Session Sync

No more manual swapping. When a request in **Repeater** or **Intruder** is highlighted with a specific color (role), ZeroX automatically detects the highlight and replaces the `Authorization` header with the latest cached token for that color before the request is sent.

### 📊 Instant Auth Matrix Generator

Generate an instant privilege escalation matrix. Right-click any request -> **ZeroX** -> **Generate Auth Matrix**. ZeroX will automatically send the request using all currently cached session tokens (plus an unauthenticated request) and display the results (Status Code, Response Length, Similarity) in the **ZeroX Matrix** tab.

---

## 🛠️ Getting Started

### Prerequisites

- **Java JDK 11** or higher
- **Apache Maven**
- **Burp Suite Professional/Community** (Modern API supported)

### Building from Source

1. Clone the repository.
2. Navigate to the project directory.
3. Execute the build command:

```powershell
mvn clean package
```

4. Find the compiled result at `target/zero-x-2.0.0.jar`.

### Installation

1. Open Burp Suite.
2. Navigate to the **Extensions** tab.
3. Click **Add** and select **Extension type: Java**.
4. Browse to `target/zero-x-2.0.0.jar` and click **Next**.

---

## 📖 Deep Dive: Usage Guide

### 1. The Firefox Bridge

ZeroX pairs perfectly with the **[ZeroX Firefox Plugin](https://addons.mozilla.org/en-US/firefox/addon/zerox/)**.

- It detects the `x-zerox-color` header injected by the plugin.
- Simply name your Firefox containers starting with `zerox-` (e.g., `zerox-admin`, `zerox-user`).
- Traffic originating from these containers will be colored automatically in Burp.

### 2. Replacing Headers in Repeater/Proxy

1. Right-click any request in Burp Suite (e.g., in Proxy History or Repeater).
2. Choose **ZeroX** -> **Select Auth**.
3. Choose the container color whose session you want to use.
4. ZeroX replaces the `Authorization` header in the request on the fly using the latest intercepted token for that container.

### 3. Generating an Auth Matrix

1. Intercept or select a request in Repeater.
2. Right-click -> **ZeroX** -> **Generate Auth Matrix**.
3. Navigate to the **ZeroX Matrix** tab to see the results.
4. The table displays how different roles (colors) respond to the same endpoint, highlighting potential IDORs or privilege escalation vulnerabilities.

---

## 🛡️ Disclaimer

This software is provided for **educational and ethical security testing** purposes only. Always obtain explicit written permission before testing any target.
