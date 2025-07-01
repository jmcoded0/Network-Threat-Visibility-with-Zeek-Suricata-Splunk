# 🛡️ Zeek-Suricata-Splunk Network Visibility Lab

## 🔍 Project Overview

This project documents the full setup of a virtual **Network Security Monitoring (NSM)** lab, combining powerful open-source tools — **Zeek**, **Suricata**, and **Splunk** — to simulate, detect, and analyze network threats in a controlled environment.

My goal is to build hands-on experience in packet-level traffic analysis, intrusion detection, log correlation, and SIEM operations — the kind of skills real SOC analysts use every day.

> 🔗 This is a continuation of my earlier work:  
> - [🔗 Splunk Cybersecurity Lab](https://github.com/jmcoded0/Splunk-Cybersecurity-Lab)  
> - [🔗 Network Monitoring & IDS Lab (Suricata)](https://github.com/jmcoded0/Network-Monitoring-IDS-Lab)

## 🎯 Objectives

- Set up a secure, isolated lab using VirtualBox
- Install and configure **Suricata** for signature-based IDS
- Deploy **Zeek** for behavioral network monitoring (NSM)
- Centralize logs from Zeek & Suricata into **Splunk**
- Simulate attacks using **Metasploitable2**
- Analyze alerts and events via **Splunk dashboards**
- Practice Linux networking and system administration
- Document every step with screenshots and clear explanations

## 🧰 Tools & Technologies

- **VirtualBox** – For virtualization
- **Kali Linux** – Main analyst box (Zeek + Suricata + Splunk Forwarder)
- **Metasploitable2** – Vulnerable target machine
- **(Optional)** Windows 10 or Ubuntu as extra victims
- **Splunk Enterprise** – For centralized log analysis
- **Zeek** – Behavioral Network Security Monitor
- **Suricata** – IDS/IPS engine
- **Nmap**, **Wireshark**, and other Kali tools

## 🖥️ Lab Architecture

- **Kali Linux VM**: Dual NICs (NAT + Host-Only), runs Zeek, Suricata, and sends logs to Splunk
- **Metasploitable2 VM**: Host-only adapter, serves as attacker target
- **Splunk**: Deployed either on host or separate VM for analysis

## ✅ Skills Demonstrated

- Network traffic capture and analysis
- IDS/IPS rule tuning (Suricata)
- Zeek log interpretation (conn, dns, http, ssl, weird, etc.)
- Splunk log ingestion and search queries
- Custom dashboard creation
- Network isolation, routing, and Linux CLI
- Incident triage using SIEM data

## 📈 Future Enhancements

- Add Sysmon + Windows logging for EDR simulation
- Integrate OpenVAS/Nessus for vulnerability management
- Expand Splunk with alerting and correlation rules
- Use real packet captures to test detection accuracy
- Deploy Elastic Stack (ELK) for alternate SIEM perspective

## 🖼️ Screenshots

> *(To be added)*  
> Expect annotated screenshots of:
> - Suricata alerts (`eve.json`)  
> - Zeek log outputs  
> - Splunk dashboards and detection queries  
> - Network diagram of the lab setup

## 📄 Full Documentation

👉 [View the full step-by-step documentation with screenshots](https://github.com/jmcoded0/Network-Monitoring-IDS-Lab/blob/main/Documenting.md)

---

## 👨‍💻 Author

**Johnson Mathew**  
Cybersecurity Analyst | SIEM | Cloud Security | Threat Detection  
📎 [GitHub Profile](https://github.com/jmcoded0)  
🌐 [https://jmcoded.site](https://jmcoded.site)

---

This project reflects my personal growth in cybersecurity and my passion for building realistic lab environments that simulate real-world threats and detections. I'm always open to feedback, collaboration, or mentorship.
