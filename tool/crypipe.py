import os
import re
import string
import subprocess
import socket
import threading
from rich.console import Console
from rich.theme import Theme
import typer
from typer import colors
import sublist3r 
from markdown_pdf import MarkdownPdf
from markdown_pdf import Section
from src.ReportGenerator import ReportGenerator
from src.DirbScanner import DirbScanner
from src.NucleiScanner import NucleiScanner
from src.NmapScanner import NmapScanner
from src.JoomScanner import JoomScanner
from src.NiktoScanner import NiktoScanner
from src.FuffScanner import FuffScanner



app = typer.Typer()
custom_theme = Theme({
    "info": "bold yellow",
    "success": "bold green",
    "error": "bold red",
    
})
spinner_style = 'bold yellow'
console = Console(theme=custom_theme)


DOMAIN_STR = "DOMAIN"
SPACES = 100



def banner():
    cry_banner = f"""
                    (        )  (    (    (         
               (    )\ )  ( /(  )\ ) )\ ) )\ )      
               )\  (()/(  )\())(()/((()/((()/( (    
             (((_)  /(_))((_)\  /(_))/(_))/(_)))\   
             )\___ (_)) __ ((_)(_)) (_)) (_)) ((_)  
            ((/ __|| _ \\ \ / / | _ \|_ _|| _ \| __| 
             | (__ |   / \ V / |  _/ | | |  _/| _|  
              \___||_|_\  |_|  |_|  |___||_|  |___|                                         
Cry Pipeline is a tool for analyzing subdomains and scanning IPs.
It allows you to gather information about the subdomains of a specified domain
and perform an Nmap scan on them to identify the running services.
"""
    
    typer.secho(cry_banner, fg=colors.RED, bold=True)
    typer.secho("\nUsage:", fg=colors.BRIGHT_MAGENTA, bold=True)
    typer.secho("python3 crypipe.py [OPTIONS] --domain DOMAIN\n", fg=colors.YELLOW, bold=True)
    typer.secho("Arguments:", fg=colors.BRIGHT_MAGENTA, bold=True)
    typer.secho("--domain, -d TEXT       Domain to scan (REQUIRED)\n", fg=colors.YELLOW, bold=True)
    typer.secho("Options:", fg=colors.BRIGHT_MAGENTA, bold=True)
    typer.secho("--all-subdomains, -a    Process all subdomains (default: False)\n", fg=colors.GREEN, bold=True)



def get_subdomains(domain):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{domain}_scan")
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, f"preliminary_subdomains_scan_{domain}.txt")

    subdomains = sublist3r.main(domain, 40, output_path, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    subdomains = list(subdomains)
    subdomains.insert(0, domain)
    return subdomains

def get_ip_addresses(hostname):
    try:
        return socket.gethostbyname(hostname.strip())
    except Exception:
        return None

def process_domain(domain: str, output_filename: str, process_all_subdomains: bool):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{domain}_scan")
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, output_filename)
    original_ip = ''


    subdomains = get_subdomains(domain) if process_all_subdomains else [domain]
    reachable_subdomains = []
    all_ip_addresses = []
    with open(output_path, 'w') as output_file:
        for subdomain in subdomains:
            ip_address = get_ip_addresses(subdomain)
            if subdomain == domain:
                original_ip = ip_address
            if ip_address:
                all_ip_addresses.append(ip_address)
                reachable_subdomains.append(subdomain)
                output_file.write(f"{subdomain}{' ' * (SPACES - len(subdomain))}{ip_address}\n")
            else:
                output_file.write(f"{subdomain}{' ' * (SPACES - len(subdomain))}No IP, maybe it is down or unreachable\n")
    
    all_ip_addresses.sort()
    return (all_ip_addresses, reachable_subdomains, original_ip)


def bind_unique_IPs_to_domains(filename, domain):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{domain}_scan")
    file_path = os.path.join(output_directory, filename)
    ip_domains = {}
    with open(file_path, 'r') as file:
        #jump the "DOMAIN IP" line
        next(file)
        for line in file:
            line = line.strip()
            if line:
                parts = line.split()
                domain = parts[0]
                ip = parts[-1]
                if ip != "No":
                    ip_domains.setdefault(ip, []).append(domain)
    return ip_domains

def sort_file(input_filename, domain):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{domain}_scan")
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, input_filename)



    with open(output_path, 'r') as f:
        lines_with_ip = []
        lines_without_ip = []
        for line in f:
            if "No IP, maybe it is down" in line:
                lines_without_ip.append(line.strip())
            else:
                lines_with_ip.append(line.strip())
    
    lines_with_ip.sort(key=lambda x: x.split()[-1])



    with open(output_path, 'w') as f:
        f.write(f"DOMAIN{' ' * (SPACES - len(DOMAIN_STR))}IP ADDRESS\n")
        for line in lines_with_ip:
            f.write(line + '\n')
        for line in lines_without_ip:
            f.write(line + '\n')

def remove_duplicates_and_save(all_ip_addresses, domain):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{domain}_scan")
    output_filename="reachable_and_unique_scanned_IPs.txt"
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, output_filename)

    unique_ip_addresses = list(set(all_ip_addresses))
    with open(output_path, "w") as ip_file:
        for ip in unique_ip_addresses:
            ip_file.write(ip + "\n")
    console.print("Unique IP addresses saved to IPs.txt.")
    return unique_ip_addresses




@app.command()
def main(domain: str = typer.Option('', "--domain", "-d", help="Domain to scan (REQUIRED)"), all_subdomains: bool = typer.Option(False, "--all-subdomains", "-a", help="Process all subdomains (default: False)"), report: bool = typer.Option(False, "--report", "-r", help="Create the report (default: False) (Execute first the scan and then create the  report)") ):
    banner()
    if '' == domain:
        return
    
    if report:
        #ReportGenerator(domain, binded_ips, all_subdomains).create_main_domain_report()
        pass
    else:
        status = console.status(f"[{spinner_style}][STEP 1] Preliminary setup -> I'm scanning subdomains...", spinner_style=spinner_style)
        with status:
            filename=f"subdomains_with_IPs_{domain}.txt"
            (all_ip_addresses, domains, original_ip) = process_domain(domain=domain, output_filename=filename, process_all_subdomains=all_subdomains)
            unique_ip_addresses=remove_duplicates_and_save(all_ip_addresses=all_ip_addresses, domain=domain)
            sort_file(input_filename=filename,domain=domain )
            binded_ips = bind_unique_IPs_to_domains(filename=filename, domain=domain)

            #console.print(binded_ips)
        
        status.stop()

        print(domain)
        print(domains)
    

        dirb_scanner = DirbScanner(original_domain=domain, console=console, domains=domains)
        nuclei_scanner = NucleiScanner(original_domain=domain, domains=domains, console=console)
        nmap_scanner = NmapScanner(original_domain=domain, original_ip=original_ip, unique_ips=unique_ip_addresses, console=console)
        joom_scanner = JoomScanner(original_domain=domain, domains=domains, console=console)
        nikto_scanner = NiktoScanner(original_domain=domain, domains=domains, console=console)
        ffuf_scanner = FuffScanner(original_domain=domain, domains=domains, console=console)


        status = console.status(f"[{spinner_style}][Step 2 - Nuclei, Joomscan, Nmap, Dirb, ffuf] I'm executing my activities in parallel... You will be noticed when the activities are done. Let me cook bro 🍝🍝", spinner_style=spinner_style)
        with status:
        
            nmap_thread = threading.Thread(target=nmap_scanner.scan_with_nmap_IPs, args=())
            joomla_thread = threading.Thread(target=joom_scanner.scan_with_joomla, args=())
            dirb_thread = threading.Thread(target=dirb_scanner.scan_with_dirb, args=())
            nikto_thread = threading.Thread(target=nikto_scanner.scan_with_nikto, args=())
            nuclei_thread = threading.Thread(target=nuclei_scanner.scan_with_nuclei, args=())
            ffuf_thread = threading.Thread(target=ffuf_scanner.scan_with_ffuf, args=())


            #nmap_thread.start()
            #joomla_thread.start()
            #nuclei_thread.start()
            #dirb_thread.start()
            #nikto_thread.start()
            ffuf_thread.start()

            #nmap_thread.join()
            #joomla_thread.join()
            #nuclei_thread.join()
            #dirb_thread.join()
            #nikto_thread.join()
            ffuf_thread.join()
            

        

        status.stop()

if __name__ == "__main__":
    app()
