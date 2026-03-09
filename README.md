# ReconX v2.5 - Network Reconnaissance Tool

**ReconX** is a lightweight, **multithreaded** network **reconnaissance** tool written in C. It combines a high-speed **Port Scanner with SYN Scan** , **Directory Buster** , **Ping Sweeper** , **DNS Enumerator**, **Services Grabber**, **LAN Sniffer** ,**ARP Poisoner** and a **crt.sh Enumerator** into a single CLI utility, designed for CTFs, penetration testing, and educational purposes.

## Features
* **SQLite Database**: SQLite-backed scan history to store and query past reconnaissance results.
* **Multithreaded Port Scanner**: fast TCP connect scanning using 15 concurrent threads by default , can also do a stealthy SYN Scan
* **Service Version Detection**: Automatically identifies common services (SSH, HTTP, FTP, SMTP, POP3, IMAP) via banner grabbing.
* **Directory Buster**: specific module to brute-force web server directories using a wordlist.
* **Advanced Interactive CLI**: Metasploit-inspired modular interface with dynamic prompts, structured module options, and clean colorized output.
* **Ping Sweeper**: fast, multithreaded ping sweeper , checks every IP in range of a given IP
* **DNS Enumerator**: Scans quickly DNS Subdomains of a given domain
* **Service Grabber**: Makes a comprehensive scan on a port and checking for 17 diffrent popular services (HTTP/S, SSH, FTP, SMTP, SMB, MYSQL, REDIS and more..)
* **LAN Sniffer**: Sniffes packets in the host network and extracts from them the MAC and IP addresses (that are from/to the host network)
* **ARP Poisoner**: Sends ARP replies on the local network to manipulate IP-to-MAC mappings between devices, And then acts as a MiTM and sniffes packets
* **crtsh**: Enumerate subdomains using crt.sh certificate transparency logs

## 📂 Project Structure

```text
.
├── include/           # Header files (.h)
├── tools/             # Implementation of scanner modules
│   ├── port_scanner.c
│   ├── dir_buster.c
│   ├── ping_sweeper.c
│   ├── dns_enum.c
│   ├── service_grabber.c
│   ├── lan_sniffer.c
│   ├── arp_poisoner.c
│   ├── crtsh.c
│   ├── db_manager.c
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

## Usage
Run the tool from the terminal. ReconX now uses an interactive, metasploit-style CLI.

```./reconx```

After launching, you will enter the interactive console:
``` reconx > ```

## Core Commands
### Main menu commands: 

Command | Description |
| --- | --- |
help | Show available modules |
use `module` | Select a module |
exit | Exit ReconX |
show history | Shows the history of which scans have been performed
show scans `id` | Shows the results of the `id` scan |

### In-Module commands:

Command | Description |
| --- | --- |
show | Shows the available values to set in the selected module |
set | Sets a value inside a module | 
run | Runs the selected module with the selected options |
back | Goes back to the main menu |


## Available Modules
Module | Description |
| --- | --- |
port_scanner | Scan for open TCP ports |
dir_buster | Directory brute-forcing on web servers |
ping_sweeper | Discover active hosts via ICMP |
dns_enum | Scan for DNS Subdomains |
service_grabber | Scans a given port for the service running on it |
lan_sniffer | Sniffs the LAN and prints MAC and IP addresses |
arp_poisoner | Manipulates IP-to-MAC mappings between devices and sniffes packets |
crtsh | Enumerate subdomains using crt.sh |

*More comming soon..!*

## Demo
![Video Project 3 (1)](https://github.com/user-attachments/assets/3706feb6-a0d7-4f82-b99e-e179eb57e14e)



## ⚠️ Disclaimer
This tool is created for **educational purposes and authorized testing only**. The author is **not responsible** for any misuse or damage caused by this program. Always ensure you have permission before scanning a target.
