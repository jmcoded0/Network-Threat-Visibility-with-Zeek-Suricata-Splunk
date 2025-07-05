# 🛡️🛡️🛡️ Zeek & Splunk Integration: Advanced Network Visibility Lab - Continuation

This project builds upon an existing cybersecurity lab environment, extending its capabilities by integrating Zeek (Network Security Monitor) for deep network telemetry and enhancing Security Information and Event Management (SIEM) with Splunk to centralize and analyze both Zeek and Suricata logs.

## 📝 **Project Context & Existing Lab Components**

### **My Action:**

I've already established a robust virtual lab environment. My Kali Linux VM is configured as both an attacker and a monitoring station, while Metasploitable2 serves as my vulnerable target. Both are safely contained within a VirtualBox Host-Only Network, ensuring isolation. Suricata, my Intrusion Detection System, is actively running on Kali, already configured to monitor the Host-Only interface and generate alerts in `eve.json`. This current project's goal is to layer Zeek for deeper network visibility and then integrate both Zeek and Suricata logs into Splunk for centralized analysis and threat hunting. I'm building on a solid foundation, allowing me to focus on advanced NSM and SIEM integration.

![image]![image](https://github.com/user-attachments/assets/bed26a46-f0ce-4006-b171-b49cb8508c17)


---

## 🗄️ **Phase 1: Zeek NSM Deployment & Configuration**

This phase focuses on the installation, basic configuration, and verification of Zeek, a powerful Network Security Monitor, on the Kali Linux VM.

### 1.1. **Considering Zeek Repository Management**

### **My Action:**

While Kali Linux often includes Zeek in its default repositories, best practice for obtaining the latest versions and avoiding potential dependency conflicts (like those sometimes seen with `libc6` on older Kali setups) often involves adding the official Zeek package repository. However, for this project, I proceeded with a direct installation using Kali's default packages, which proved successful for setting up Zeek without needing to add an external repository in this instance.

### 1.2. **Installing and Verifying Zeek**

### **My Action:**

I installed Zeek directly using Kali's package manager, `apt`. Once the installation was complete, I immediately verified its successful deployment and confirmed the installed version.

```bash
# Install Zeek from Kali's default repositories
sudo apt update
sudo apt install zeek -y
```
![VirtualBox_Kali Linux_02_07_2025_00_11_22](https://github.com/user-attachments/assets/8080e639-fa81-41f4-b345-b664321a6a84)

### 1.3. **Configuring Zeek for Lab Monitoring**

### **My Action:**

Now that Zeek's presence is verified, I need to tell it precisely what to monitor and how to classify traffic. This involves editing two critical configuration files: `node.cfg` to specify the monitoring interface, and `networks.cfg` to define my internal network ranges.

First, I made sure my Kali VM's Host-Only adapter (`eth1`) was **enabled** in VirtualBox settings, and `Promiscuous Mode` was set to **`Allow All`**. This is crucial for Zeek to capture all traffic on that segment.

Then, I opened `node.cfg` using `nano`:

```bash
sudo nano /opt/zeek/etc/node.cfg
```
![image](https://github.com/user-attachments/assets/f701c021-b663-468a-8ae5-42232d6a05d7)
Inside node.cfg, I located the [zeek] section and made sure the interface= parameter was set to eth1. This tells Zeek to listen on my Host-Only network adapter, i ensure only eth1 is active for this Zeek instance. I also confirmed type=standalone for my single-node deployment.
```bash
sudo nano /opt/zeek/etc/networks.cfg
```
![image](https://github.com/user-attachments/assets/33edbb50-65d4-4c88-ab8f-2ce6938de610)
In networks.cfg, I defined my isolated lab network's IP range. I commented out the default broad ranges and added my specific Host-Only network subnet: 192.168.117.0/24. This helps Zeek understand which traffic is internal to my lab versus external.

### 1.4. **Starting Zeek and Verifying Initial Logs**

### **My Action:**

With Zeek successfully configured to monitor `eth1` and understand my lab network, it's time to bring it online. I'll use `zeekctl`, Zeek's command-line control utility, to deploy the configuration and start the Zeek process.

Before starting, I double-checked that my **Host-Only adapter (`eth1`)** in VirtualBox was set to `Promiscuous Mode: Allow All` for my Kali VM. This is vital for Zeek to capture all traffic.

Then, in my Kali terminal, I executed the following commands:

```bash
# Navigate to Zeek's bin directory (where zeekctl is located)
cd /opt/zeek/bin/

# Deploy Zeek's configuration. This processes node.cfg and prepares Zeek to run.
sudo ./zeekctl deploy

# Start Zeek. This initiates the network monitoring process.
sudo ./zeekctl start

# Check Zeek's status to confirm it's running
sudo ./zeekctl status
```
![image](https://github.com/user-attachments/assets/54f5a485-b5d0-454f-9136-5789a563f5b9)
After starting Zeek, I needed to verify that it was actively generating log files. Zeek creates a new timestamped directory for each monitoring session under /opt/zeek/logs/, with a convenient symlink called current always pointing to the latest session. I navigated into this current directory and listed its contents.
```bash
# List the generated log files to see what's there
sudo ls -l /opt/zeek/logs/current/

# Tail the connection log to see live data as you generate traffic
sudo tail -f /opt/zeek/logs/current/conn.log
```
![image](https://github.com/user-attachments/assets/261c946a-9e81-489c-9629-8a9c70ff2fbb)
To see live data, I then used tail -f on conn.log (Zeek's connection log). While tail -f was running, I performed some basic network activity between Kali and Metasploitable2 (e.g., a simple ping 192.168.117.3 and nmap -sn 192.168.117.0/24) to ensure new entries appeared in real-time
![VirtualBox_Kali Linux_02_07_2025_23_28_44](https://github.com/user-attachments/assets/761e9f59-8177-4ac1-a85f-4226f29ccacd)

2.1. Installing Splunk Universal Forwarder
My Action:
The Splunk Universal Forwarder is a critical component for collecting and forwarding logs to Splunk Enterprise. For this project, the Universal Forwarder was already installed and available on my Kali Linux VM from previous lab projects. Therefore, the direct installation steps typically involved in this section were not required during this phase. This allowed me to proceed directly to its configuration.

### 2.2. **Configuring the Universal Forwarder for Zeek and Suricata Logs**

### **My Action:**

Now that the Splunk Universal Forwarder is installed on my Kali VM, I need to configure it to collect the Zeek and Suricata logs and send them to my Splunk Enterprise instance. This involves editing two key configuration files within the forwarder's directory: `inputs.conf` to define the log sources, and `outputs.conf` to specify the Splunk receiver.

First, I navigated to the forwarder's default configuration directory:

```bash
cd /opt/splunkforwarder/etc/system/local/
```
Then, I opened inputs.conf for editing
Inside inputs.conf, I added stanzas to monitor the Zeek and Suricata log directories. Zeek logs are in /opt/zeek/logs/current/ (which is a symlink to the current timestamped session), and Suricata logs (eve.json) are typically in /var/log/suricata/.
[monitor:///opt/zeek/logs/current/]
```bash
disabled = false
index = zeek
sourcetype = _json

[monitor:///var/log/suricata/eve.json]
disabled = false
index = suricata
sourcetype = suricata_eve
```
![image](https://github.com/user-attachments/assets/8081fd8b-d71b-4695-a9b3-aa0cdf721191)
After adding these lines, I saved and closed inputs.conf (Ctrl+X, Y, Enter).
Next, I opened outputs.conf
```bash
sudo nano outputs.conf
```
In outputs.conf, I defined my Splunk Enterprise instance as the default receiver. Since Splunk Enterprise is installed on the same Kali VM, I configured the forwarder to send logs to 127.0.0.1 (localhost) on the default Splunk receiving port 9997.
```bash
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 127.0.0.1:9997

[tcpout-server://127.0.0.1:9997]
```
After adding these lines, I saved and closed outputs.conf (Ctrl+X, Y, Enter).
![VirtualBox_Kali Linux_03_07_2025_00_30_05](https://github.com/user-attachments/assets/78e35ec6-5e5e-419e-b7fa-f72a35babeed)

Finally, to apply the new configurations, I restarted the Splunk Universal Forwarder
![VirtualBox_Kali Linux_03_07_2025_00_07_21](https://github.com/user-attachments/assets/c0a8ce3e-40e5-43c8-a7cc-3d3dded0dead)

### 2.3. **Configuring Splunk Enterprise to Receive Logs**

### **My Action:**

With the Splunk Universal Forwarder on Kali Linux now configured to send logs, the next crucial step is to set up Splunk Enterprise to **receive** these incoming data streams. This involves enabling a receiving port on the Splunk instance.

Before proceeding, I needed to ensure my Kali Linux VM had the necessary network connectivity for accessing the internet (which might have been disabled during previous configurations) and that my Splunk Enterprise instance was actively running.

First, I **restarted my Kali Linux VM**. Upon reboot, I addressed the network connectivity by going into my VirtualBox settings for the Kali VM. I **unchecked Adapter 2 (NAT)**, which I had previously configured for specific purposes, to ensure my primary network adapter (`eth0`) could regain internet access. This step was critical for the Splunk web interface to function properly, especially if it relies on any external resources or updates.

Next, I ensured my Splunk Enterprise instance was running. I opened a terminal on my Kali VM and executed the command to start the Splunk service:

```bash
sudo /opt/splunk/bin/splunk start
```

I waited for the terminal to confirm that the `"Splunk Web interface started at https://127.0.0.1:8000"` message appeared, indicating that Splunk Enterprise was fully operational and its web interface was accessible.

![image](https://github.com/user-attachments/assets/130724d4-13d1-4695-b649-32929f60014b)

With Splunk Enterprise running and network connectivity confirmed, I then logged into my Splunk Enterprise web interface. Since Splunk is installed on the same Kali VM, I accessed it directly from a web browser within the Kali machine by navigating to:

```
https://127.0.0.1:8000
```

Once logged in, I navigated to **Settings > Data Inputs**.

Under the **"Local inputs"** section, I clicked on **"TCP"**. This is where I configured a new TCP data input for the logs coming from the Universal Forwarder.

I clicked **"New Local TCP Input"** or **"Add new"** to create a new listener.

For the **Port**, I entered `9997`, which is the default port the Universal Forwarder is configured to send logs to in `outputs.conf`. I ensured the port was open and not blocked by any firewall rules on the Kali VM.

I clicked **"Next"**.

On the "Input Settings" screen, I specified the following:

* **Source type**: I needed to add two distinct data inputs, one for Zeek logs and one for Suricata logs.
  * For **Zeek logs**: I selected **"Select"** and then explicitly chose `zeek` as the source type. It's crucial to note that while some network security data might be in JSON, Zeek logs are typically in a **tab-separated value (TSV)** format. Incorrectly setting this to `_json` in earlier attempts led to data corruption, which was resolved by specifically using `sourcetype=zeek` to ensure proper parsing.
  * For **Suricata logs**: I selected **"Select"** and chose `suricata_eve` as the source type, which is specifically designed for Suricata's EVE JSON output.

* **Index**: I created two new indexes for better data organization:
  * For Zeek logs, I entered `zeek`.
  * For Suricata logs, I entered `suricata`.

* **Host field value**: I set this to `kali-nsm` to easily identify the source of these logs in Splunk, indicating they originated from my Kali Network Security Monitoring machine.

I then clicked **"Review"** and finally **"Submit"** to create each data input. I repeated this process for both the Zeek and Suricata log types, ensuring each had its own dedicated index and appropriate sourcetype.

![VirtualBox_Kali Linux_03_07_2025_01_15_28](https://github.com/user-attachments/assets/32569cb9-6023-45d1-babf-16ca460854c8)

After setting up the input, I generated some new network traffic from Kali (e.g., `ping` to Metasploitable2, simple web browse to a target, and Nmap scans) to ensure logs were actively being sent by the forwarder and successfully received by Splunk. This confirmed that both Zeek and Suricata logs were being ingested correctly into their respective indexes with proper sourcetypes and field extraction.
![VirtualBox_Kali Linux_03_07_2025_17_13_40](https://github.com/user-attachments/assets/f247ffeb-98be-4400-b419-77a7d08956ee)

### 2.4. **Data Verification and Initial Exploration in Splunk**

### **My Action:**

With the Universal Forwarder sending logs and Splunk Enterprise configured to receive them, the immediate next step was to thoroughly verify that the network security data was not only arriving but also being correctly parsed and indexed. This involved ensuring that the previously observed data corruption (`00000` characters) was absent and that Splunk was successfully extracting meaningful fields from both Zeek and Suricata logs.

First, I logged into my Splunk Enterprise web interface. My primary goal was to confirm the integrity of the **Zeek logs**, as this had been a key challenge.

I navigated to the **Search & Reporting** app and executed a targeted search for Zeek data:

```splunk
index=zeek sourcetype=zeek
```

I set the time range to **"Last 15 minutes"** to focus on recent activity generated after the final configuration adjustments. I observed the search results closely. Crucially, I confirmed that:

- The data was indeed present, showing a growing number of events.
- The **sourcetype** for these events was accurately identified as `zeek`, confirming that the specific receiver configuration on Splunk Enterprise was correctly overriding any default auto-detection.
- The raw event data was clean and free of the `00000` (null byte) corruption that plagued earlier attempts.
- Splunk was actively extracting fields relevant to Zeek logs (e.g., `id.orig_h`, `id.resp_h`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, etc.), which were visible in the **"Interesting Fields"** and **"Selected Fields"** sections on the left pane. This indicated that the field extraction rules (either built-in or from custom `props.conf`/`transforms.conf`) were being applied effectively.

![VirtualBox_Kali Linux_03_07_2025_17_34_35](https://github.com/user-attachments/assets/e919c11a-b4cb-433d-ad93-609ca3a7b796)


Next, to ensure all data streams were functioning as expected, I performed a similar verification for **Suricata logs**:

```splunk
index=suricata sourcetype=suricata_eve
```

I again set the time range to **"Last 15 minutes."** I confirmed that Suricata alerts and events were flowing in, correctly identified with `sourcetype=suricata_eve`, and that relevant fields like `alert.signature`, `src_ip`, `dest_ip`, `dest_port`, `proto`, and `flow_id` were being extracted. This validated the complete data ingestion pipeline.

![VirtualBox_Kali Linux_03_07_2025_17_34_35](https://github.com/user-attachments/assets/107c3a4c-e4fc-4fee-9782-f0d5148a7673)

### 2.5. **Initial Security Monitoring and Visualization**

### **My Action:**

After confirming that logs from both Zeek and Suricata were successfully being ingested into Splunk, I moved on to explore the data for threat detection and visibility. Since not all predefined searches returned results, I adapted my approach based on the fields that were actually available from the logs.

---

#### 🔍 Viewing Raw Zeek Logs

To understand what kind of network data Zeek was capturing, I used a table command to list all available fields:

```splunk
index=zeek sourcetype=zeek_custom_tsv | table *
```

This allowed me to explore connection metadata such as IPs, ports, protocols, and session details. It also helped confirm that Zeek was actively logging new network events.

![VirtualBox_Kali Linux_05_07_2025_01_15_12](https://github.com/user-attachments/assets/4715aa54-7be1-41a1-8da4-80c47b21d0f8)

---

#### 📊 Monitoring Suricata Alerts with Key Fields

To focus on the most relevant Suricata alert data, I used a more refined table search that highlights the timestamp, alert signature, categories, IP addresses, and protocol:

```splunk
index=suricata sourcetype=suricata_json | table _time, alert.signature, alert.category, src_ip, dest_ip, src_port, dest_port, proto
```

This gave me a cleaner and more structured overview of all detected alerts, which is easier to analyze and visualize in Splunk.

![image](https://github.com/user-attachments/assets/d060318b-abdc-410a-8cbb-1eb101d7bede)


---

#### 📈 Bonus Visualization: Top Source IPs from Zeek

I also created a basic chart to identify the most active source IPs on the network:

```splunk
index=zeek sourcetype=zeek_custom_tsv | table _time, id.orig_h, id.resp_h, proto
```

I saved this as a **report** and visualized it using a **bar chart** to highlight top talkers in the lab environment.

![VirtualBox_Kali Linux_05_07_2025_01_19_55](https://github.com/user-attachments/assets/e8e00102-6499-4b78-9a50-54639ce34fb2)

---

These visualizations gave me a practical view into what’s happening in the network and helped me validate that my lab setup (including Zeek and Suricata integration with Splunk) was working properly. Instead of focusing on pre-built dashboards, I built these queries from scratch based on the data I had — which was a valuable learning experience on its own.

## 🧠 Final Thoughts & Lessons Learned

This lab was **by far the most challenging project I’ve worked on so far** in my cybersecurity journey. Integrating Zeek and Suricata into Splunk inside a fully isolated VirtualBox environment came with **multiple technical roadblocks** — from broken sourcetypes, log parsing issues, `00000` TSV corruption, network interface confusion, Splunk data input misconfigurations, and more. At times, the logs weren’t even showing, and I had to troubleshoot from the ground up — manually inspecting field extractions, rewriting search queries, and rethinking how data flows.

But through all of that, I **learned more than any tutorial could teach me**. I now understand:
- How to build a working NSM pipeline from raw packets to visual dashboards.
- How to debug Splunk Universal Forwarder and sourcetype issues.
- Why proper indexing and field extraction **makes or breaks your SIEM visibility**.
- How Zeek and Suricata complement each other — Zeek for deep protocol insight, Suricata for signature-based detection.

Most importantly, I learned the **value of patience, persistence, and adapting** when things don’t work on the first try.

This wasn’t just a lab setup — it was a real-world simulation of what cybersecurity professionals face daily in blue team operations.

