# Zeek & Splunk Integration: Advanced Network Visibility Lab - Continuation

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
   I waited for the terminal to confirm that the "Splunk Web interface started at https://www.google.com/url?sa=E&source=gmail&q=https://127.0.0.1:8000" message appeared, indicating that Splunk Enterprise was fully operational and its web interface was accessible.
![image](https://github.com/user-attachments/assets/130724d4-13d1-4695-b649-32929f60014b)

With Splunk Enterprise running and network connectivity confirmed, I then logged into my Splunk Enterprise web interface. Since Splunk is installed on the same Kali VM, I accessed it directly from a web browser within the Kali machine by navigating to https://127.0.0.1:8000.
Once logged in, I navigated to **Settings > Data Inputs**.

Under the **"Local inputs"** section, I clicked on **"TCP"**. This is where I configured a new TCP data input for the logs coming from the Universal Forwarder.

I clicked **"New Local TCP Input"** or **"Add new"** (depending on the Splunk version's exact wording) to create a new listener.

For the **"Port"**, I entered `9997`, which is the default port the Universal Forwarder is configured to send logs to in `outputs.conf`. I ensured the port was open and not blocked by any firewall rules on the Kali VM.

I clicked **"Next"**.

On the **"Input Settings"** screen, I specified the following:
* **Source type**: I needed to add two distinct data inputs, one for Zeek logs and one for Suricata logs.
    * For **Zeek logs**: I selected **"Select"** and then chose `_json` as the source type, as Zeek logs are primarily in JSON format.
    * For **Suricata logs**: I also selected **"Select"** and chose `suricata_eve` as the source type, which is specifically designed for Suricata's EVE JSON output, or `_json` if `suricata_eve` was not readily available.
* **Index**: I created two new indexes for better data organization:
    * For Zeek logs, I entered `zeek`.
    * For Suricata logs, I entered `suricata`.
* **Host field value**: I set this to `kali-nsm` to easily identify the source of these logs in Splunk, indicating they originated from my Kali Network Security Monitoring machine.

I then clicked **"Review"** and finally **"Submit"** to create each data input. I repeated this process for both the Zeek and Suricata log types, ensuring each had its own dedicated index and appropriate sourcetype.

After setting up the input, I generated some new network traffic from Kali (e.g., `ping` to Metasploitable2, simple web Browse to a target, or Nmap scans) to ensure logs were actively being sent by the forwarder and successfully received by Splunk.

* **Screenshot:**
    **Show your Splunk Enterprise web interface demonstrating the successful creation of the TCP inputs (e.g., a screenshot of the "Data Inputs > TCP" page showing port `9997` configured, or a screenshot of the input settings review page for `zeek` and `suricata` indexes). You should ideally have one screenshot showing the input for Zeek logs (with index `zeek` and sourcetype `_json`) and another for Suricata logs (with index `suricata` and sourcetype `suricata_eve` or `_json`).**
    Wait for the "Splunk Web interface started" message.

I logged into my Splunk Enterprise web interface, which, since Splunk is installed on the same Kali VM, I accessed via `https://127.0.0.1:8000` in a web browser on the Kali machine itself.

Once logged in, I navigated to **Settings > Data Inputs**.

Under the **"Local inputs"** section, I clicked on **"TCP"**. This is where I configured a new TCP data input for the logs coming from the Universal Forwarder.

I clicked **"New Local TCP Input"** or **"Add new"** (depending on the Splunk version's exact wording) to create a new listener.

For the **"Port"**, I entered `9997`, which is the default port the Universal Forwarder is configured to send logs to in `outputs.conf`. I ensured the port was open and not blocked by any firewall rules on the Kali VM.

I clicked **"Next"**.

On the **"Input Settings"** screen, I specified the following:
* **Source type**: I needed to add two distinct data inputs, one for Zeek logs and one for Suricata logs.
    * For **Zeek logs**: I selected **"Select"** and then chose `_json` as the source type, as Zeek logs are primarily in JSON format.
    * For **Suricata logs**: I also selected **"Select"** and chose `suricata_eve` as the source type, which is specifically designed for Suricata's EVE JSON output, or `_json` if `suricata_eve` was not readily available.
* **Index**: I created two new indexes for better data organization:
    * For Zeek logs, I entered `zeek`.
    * For Suricata logs, I entered `suricata`.
* **Host field value**: I set this to `kali-nsm` to easily identify the source of these logs in Splunk, indicating they originated from my Kali Network Security Monitoring machine.

I then clicked **"Review"** and finally **"Submit"** 
![VirtualBox_Kali Linux_03_07_2025_01_15_28](https://github.com/user-attachments/assets/957122aa-3160-4cea-9abb-c1fb402a0ff3)

After setting up the input, I generated some new network traffic from Kali (e.g., `ping` to Metasploitable2, simple web Browse to a target, or Nmap scans) to ensure logs were actively being sent by the forwarder and successfully received by Splunk.

* **Screenshot:**
    **Show your Splunk Enterprise web interface demonstrating the successful creation of the TCP inputs (e.g., a screenshot of the "Data Inputs > TCP" page showing port `9997` configured, or a screenshot of the input settings review page for `zeek` and `suricata` indexes). You should ideally have one screenshot showing the input for Zeek logs (with index `zeek` and sourcetype `_json`) and another for Suricata logs (with index `suricata` and sourcetype `suricata_eve` or `_json`).**
