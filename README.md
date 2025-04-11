# 🛠️ Automated Attack Menu – README

> “Give me a target and I’ll give you attack vectors.”  
> – This Script, probably.

---

## 📌 Overview

**Automated Attack Menu** is a Python-based tool designed to simulate a realistic red-team recon workflow. It profiles a target service through interactive questions and recommends potential attacks based on conditions like authentication, service type, network visibility, and known vulnerabilities.

It's like having your own junior pentester... minus the HR paperwork.

---

## 🔍 Features

- ✅ Interactive Target Profiling (OS, services, network, firewall, etc.)
- ✅ Intelligent Attack Recommendation Engine
- ✅ Sample Commands for each Attack (so you don’t have to Google)
- ✅ Auto-generated Summary Report (`attack_summary.txt`)
- ✅ Logs all activities to `attack_tool.log`
- ✅ Stylish CLI interface with dramatic slow typing 😎
- ✅ Keeps the window open after execution (because you asked nicely)

---

## 🚀 How to Use

### 1. **Install Python 3 (if you haven’t already)**  
This tool is Python 3 compatible.

### 2. **Run the Script**  
Double-click the `.py` file or run it from the terminal:

```bash
python3 attack_tool.py
```

### 3. **Follow the Prompts**  
Answer questions about the target (e.g., OS, service type, version info).

### 4. **Get Attack Suggestions**  
You'll get a list of attack vectors with actual example commands.

### 5. **Check Output Files**
- 📝 `attack_summary.txt` → Summary of the target and attacks
- 🪵 `attack_tool.log` → Logs of tool activity and errors

---

## 📁 Output Sample

```
Target Profile:
OS: linux
Service: web
Version: 2.2.1
Authentication: yes
...

Recommended Attacks:
- web_exploit
- brute_force
- dir_enum
...
```

---

## 📎 Requirements

- Python 3.6+
- No external libraries needed — pure standard Python

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**. Use it only on systems you own or are explicitly authorized to test. Unauthorized use may be illegal.  
I am not responsible if you use this to try and break into your neighbor's WiFi, Kevin.

---

## 🧠 Credits & Vibes

Crafted by: **Shivek Gupta**  
Inspired by: Real-life pentesting tools, sarcasm, and a little boredom

---
