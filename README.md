# ReconX v2.0 - Network Reconnaissance Tool

<pre>
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
</pre>

**ReconX** is a lightweight, **multithreaded** network **reconnaissance** tool written in C. It combines a high-speed **Port Scanner** , **Directory Buster** and a **Ping Sweeper** into a single CLI utility, designed for CTFs, penetration testing, and educational purposes.

 **Note:**
 This is version **2.0** of this tool. There are a lot more **updates** and **improvements** comming soon (and a lot more **capabilities**)

## 🚀 Features

* **Multithreaded Port Scanner**: fast TCP connect scanning using 15 concurrent threads by default.
* **Service Version Detection**: Automatically identifies common services (SSH, HTTP, FTP, SMTP, POP3, IMAP) via banner grabbing.
* **Directory Buster**: specific module to brute-force web server directories using a wordlist.
* **Flexible Scanning**: Supports both Top 1024 ports and full range (1-65535) scanning.
* **Interactive CLI**: Clean, colorized output for easy readability.
* **Ping Sweeper**: fast, multithreaded ping sweeper , checks every IP in range of a given IP

## 📂 Project Structure

```text
.
├── include/           # Header files (.h)
├── tools/             # Implementation of scanner modules
│   ├── port_scanner.c
│   ├── dir_buster.c
│   ├── ping_sweeper.c
│   └── utils.c
├── main.c             # Entry point and argument parsing
├── Makefile           # Build configuration
├── common.txt         # Default wordlist for directory busting
└── build/             # Output directory for the compiled binary
```

## 🛠️ Installation & Build
ReconX uses a ```Makefile``` for easy compilation. Ensure you have ```gcc``` and ```make``` installed.
### 1. Clone the repository:
```
git clone [https://github.com/ofri09bs/reconx.git](https://github.com/ofri09bs/reconx.git)
cd reconx
```

### 2. Compile the project:
```make```
This will compile the source code and generate the executable in build/reconx.

## 💻 Usage
Run the tool from the terminal. You must provide a target IP address and a scan mode.

## Syntax

```./build/reconx <target_ip> [options]```

## Options
Flag | Description |
| --- | --- |
-p | Run the Port Scanner (Top 1024 ports). |
-d | Run the Directory Buster (uses common.txt). |
-pa | Scan all ports (1-65535). |'
-s | Ping Sweep a given IP |
-h |Show the help menu. |

## Examples

**1. Basic Port Scan** (Top 1024 ports):```./build/reconx 192.168.1.10 -p```

**2. Full Port Scan** (Ports 1-65535):```./build/reconx 10.10.10.5 -pa```

**3. Directory Brute-Forcing**:```./build/reconx 192.168.1.10 -d```


**Note**: The Directory Buster defaults to port 80 and uses common.txt as the wordlist.

## ⚠️ Disclaimer
This tool is created for **educational purposes and authorized testing only**. The author is **not responsible** for any misuse or damage caused by this program. Always ensure you have permission before scanning a target.
