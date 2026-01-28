# Scanmylan is a simple but powerfull utility that help user to scan for host availability
# It work with PySide6 (gui) and OS ping

## Run (GUI)
```bash
python main.py
# or
python main_gui.py
```

## Run (CLI)
```bash
python main.py --network 192.168.88.0/24 --dbfile scans.sqlite --title "Scan office"
```

CTRL+C during CLI: complete stops , **not save**.

## Input network
Only IPv4 CIDR (es. `192.168.88.0/24`). A single IP will be handled as `/32`.

## Pipeline
A) Ping (process concurrency `num_process`)  
B) Retry per IP (`num_run`)  
C) FQDN (only alive)  
D) ARP (only alive)  
E) Vendor (only alive with MAC present)
