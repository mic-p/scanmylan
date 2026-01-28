# ScanMyLan

**ScanMyLan** is a simple but powerful utility designed to scan a local network and check host availability using the **operating system ping** (via subprocess).  
It is fully cross-platform and works on:

- ✅ **GUI with PySide6**
- ✅ **Automatic CLI mode**
- ✅ **Cli scan reader**
- ✅ Windows / Linux
- ✅ UI language: Italian if OS locale is Italian, otherwise English.


Optional features included:

- **FQDN resolution** (`socket.gethostbyaddr`)
- **ARP / MAC address lookup**
  - Windows: `arp -a`
  - Linux: `/proc/net/arp`
- **Vendor lookup** through the *macvendorlookup.com* API

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Run (GUI)

```bash
python main.py
# or
python main_gui.py
```

---

## Run (CLI)

Automatic scan, output printed with tabulate, and results saved into a database:

```bash
python main.py --network 192.168.1.0/24 --dbfile scans.sqlite --title "Office scan"
```

---

## Scan reader (CLI)

Scan reader that print with tabulate the results saved into a database:

```bash
python main_read_scans.py
# or
python main_read_scans.py -h
```

---

## Stop Execution

During CLI execution:

- `CTRL+C` immediately stops everything  
- **No data will be saved into the database**

---

## Network Input

Only IPv4 CIDR format is supported:

- Example: `192.168.88.0/24`
- A single IP address is automatically treated as `/32`

---

## Scan Pipeline

A) Ping concurrency (`num_process`)  
B) Retry per IP (`num_run`)  
C) FQDN resolution *(only for alive hosts)*  
D) ARP/MAC lookup *(only for alive hosts)*  
E) Vendor lookup *(only for alive hosts with MAC available)*  

