# ReconX v2.1 - Network Reconnaissance Tool

<pre>
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
</pre>

**ReconX** is a lightweight, **multithreaded** network **reconnaissance** tool written in C. It combines a high-speed **Port Scanner** , **Directory Buster** , **Ping Sweeper** and a **DNS Enumerator** into a single CLI utility, designed for CTFs, penetration testing, and educational purposes.

 **Note:**
 This is version **2.1** of this tool. There are a lot more **updates** and **improvements** comming soon (and a lot more **capabilities**)

## Features

* **Multithreaded Port Scanner**: fast TCP connect scanning using 15 concurrent threads by default.
* **Service Version Detection**: Automatically identifies common services (SSH, HTTP, FTP, SMTP, POP3, IMAP) via banner grabbing.
* **Directory Buster**: specific module to brute-force web server directories using a wordlist.
* **Flexible Scanning**: Supports both Top 1024 ports and full range (1-65535) scanning.
* **Advanced Interactive CLI**: Metasploit-inspired modular interface with dynamic prompts, structured module options, and clean colorized output.
* **Ping Sweeper**: fast, multithreaded ping sweeper , checks every IP in range of a given IP
* **DNS Enumerator**: Scans quickly DNS Subdomains of a given domain

## 📂 Project Structure

```text
.
├── include/           # Header files (.h)
├── tools/             # Implementation of scanner modules
│   ├── port_scanner.c
│   ├── dir_buster.c
│   ├── ping_sweeper.c
│   ├── dns_enum.c
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

### Core Commands
Command | Description |
| --- | --- |
help | Show available modules |
use <module> | Select a module |
exit | Exit ReconX |
show | Shows the available values to set in the selected module |
set | Sets a value inside a module | 
run | Runs the selected module with the selected options |
back | Goes back to the main menu |


### Available Modules
Module | Description |
| --- | --- |
port_scanner | Scan for open TCP ports |
dir_buster | Directory brute-forcing on web servers |
ping_sweeper | Discover active hosts via ICMP |
dns_enum | Scan for DNS Subdomains |

*More comming soon..!*

## Example

```
reconx > use port_scanner
reconx/port_scanner > show
--- shows module options ---
reconx/port_scanner > set TARGET 134.67.0.10
reconx/port_scanner > set PORTS 1-5000
reconx/port_scanner > run

--- port scanner results ---
```


## ⚠️ Disclaimer
This tool is created for **educational purposes and authorized testing only**. The author is **not responsible** for any misuse or damage caused by this program. Always ensure you have permission before scanning a target.
