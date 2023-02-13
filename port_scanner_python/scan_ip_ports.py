import argparse
from datetime import datetime
import socket
from rich.theme import Theme
from rich.console import Console

custom_theme = Theme({"success":"bold green", "error":"bold red", "detail": "italic"})
console = Console(theme=custom_theme)

parser = argparse.ArgumentParser(description='Ip ports Scanners')
parser.add_argument('-t', '--target-ip', help="the victim ip to scan", required=True)


args = parser.parse_args()
target = args.target_ip
almost_one_opened = False

console.print("-"*50)
console.print(f"Scanning: {target}")
console.print(f"Start at: {datetime.now()}")
console.print("-"*50)
try:
    console.print(f'Scanning ports, wait, you can see opened ones on this terminal...', style = "detail")
    for port in range(1, 1024):
        # AF_INET is ipv4 SOCK_STREAM is a port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # if we don't get a response in 1 sec we pass away
        socket.setdefaulttimeout(1)

        if sock.connect_ex((target, port)) == 0:
            almost_one_opened = True
            console.print(f'Port {port} is opened', style="success") 
        sock.close()
    if not almost_one_opened:
        console.print(f'No opened ports found...', style="error")
except KeyboardInterrupt:
    console.print("Program closed", style = "error")
    exit()
except socket.gaierror:
    console.print("Hostname cannot be resolved", style = "error")
    exit()
except socket.error:
    console.print("Error on connection", style = "error")
    exit()