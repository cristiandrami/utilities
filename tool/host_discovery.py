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
import nmap
from markdown_pdf import MarkdownPdf
from markdown_pdf import Section




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

def remove_non_printable(text):
    printable_chars = set(string.printable)
    filtered_text = ''.join(char for char in text if char in printable_chars)
    filtered_text = filtered_text.replace('[34m', '')
    filtered_text = filtered_text.replace('[31m', '')
    filtered_text = filtered_text.replace('[33m', '')
    filtered_text = filtered_text.replace('[0m', '')
    filtered_text = filtered_text.replace('[0m]', '')
    filtered_text = filtered_text.replace('[[92m', '')
    filtered_text = filtered_text.replace('[[34m', '')

    return filtered_text



def get_subdomains(domain):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan")
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, f"preliminary_subdomains_scan_{domain}.txt")

    subdomains = sublist3r.main(domain, 40, output_path, ports=None, silent=True, verbose=True, enable_bruteforce=False, engines=None)
    subdomains.insert(0, domain)
    return subdomains

def get_ip_addresses(hostname):
    try:
        return socket.gethostbyname(hostname.strip())
    except Exception:
        return None

def process_domain(domain: str, output_filename: str, process_all_subdomains: bool):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan")
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, output_filename)


    subdomains = get_subdomains(domain) if process_all_subdomains else [domain]
    reachable_subdomains = []
    all_ip_addresses = []
    with open(output_path, 'w') as output_file:
        for subdomain in subdomains:
            ip_address = get_ip_addresses(subdomain)
            if subdomain == ORIGINAL_DOMAIN:
                global ORIGINAL_IP
                ORIGINAL_IP = ip_address
            if ip_address:
                all_ip_addresses.append(ip_address)
                reachable_subdomains.append(subdomain)
                output_file.write(f"{subdomain}{' ' * (SPACES - len(subdomain))}{ip_address}\n")
            else:
                output_file.write(f"{subdomain}{' ' * (SPACES - len(subdomain))}No IP, maybe it is down or unreachable\n")
    
    all_ip_addresses.sort()
    return (all_ip_addresses, reachable_subdomains)


def bind_unique_IPs_to_domains(filename):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan")
    file_path = os.path.join(output_directory, filename)
    ip_domains = {}
    with open(file_path, 'r') as file:
        #jump the DOMAIN IP line
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

def sort_file(input_filename):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan")
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

def remove_duplicates_and_save(all_ip_addresses, output_filename="reachable_and_unique_scanned_IPs.txt"):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan")
    os.makedirs(output_directory, exist_ok=True)
    output_path = os.path.join(output_directory, output_filename)

    unique_ip_addresses = list(set(all_ip_addresses))
    with open(output_path, "w") as ip_file:
        for ip in unique_ip_addresses:
            ip_file.write(ip + "\n")
    console.print("Unique IP addresses saved to IPs.txt.")
    return unique_ip_addresses

"""def scan_with_nmap(unique_IPs):
    script_directory = os.path.dirname(__file__)
    output_directory = os.path.join(script_directory, "output", "network_info_gathering", "nmap")
    # Check if the output directory exists, otherwise create it
    os.makedirs(output_directory, exist_ok=True)
    nm = nmap.PortScanner()
    for ip in unique_IPs:
        nm.scan(ip.strip(), arguments='-sV  -T4')
        data=nm[ip.strip()]
        hostname = data['hostnames'][0]['name']
        ip_address = data['addresses']['ipv4']
        

        # Define the output file path
        output_file = f"nmap_{ip.strip()}_scan.txt"
        output_path = os.path.join(output_directory, output_file)
original_domain
        

        # Write the output to the file
        with open(output_path, "w") as f:
            f.write(f"Nmap scan report for {hostname} ({ip_address})\n")
            f.write("PORT\t\tSTATE\t\tSERVICE\t\tVERSION\n")

            elem_to_avoid = ['hostnames', 'addresses', 'vendor', 'status']
            for protocol in data:
                if protocol not in elem_to_avoid:
                    for port, port_data in data[protocol].items():
                        service = port_data.get('name', '')
                        version = port_data.get('version', '')
                        product = port_data.get('product', '')
                        if service and version and product:
                            f.write(f"{port}/{protocol}\t\t{port_data['state']}\t\t{service}\t\t{product} {version}\n")
                        elif service and version:
                            f.write(f"{port}/{protocol}\t\t{port_data['state']}\t\t{service}\t\t{version}\n")
                        elif service:
                            f.write(f"{port}/{protocol}\t\t{port_data['state']}\t\t{service}\n")
                        else:
                            f.write(f"{port}/{protocol}\t\t{port_data['state']}\n")

        console.print(f"nmap scan completed for {ip.strip()}. Results saved in {output_path}", style="success")"""
    

def scan_with_nmap_IPs(unique_IPs):
    script_directory = os.path.dirname(__file__)
    

    for ip in unique_IPs:
        if ip == ORIGINAL_IP:
            output_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "network_info_gathering", "nmap")
        else:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan","subdomains", "network_info_gathering", "nmap")
        
        # check if the output directory exists, if not create it
        os.makedirs(output_directory, exist_ok=True)
        output_file = f"{ip.strip()}.txt"
        output_path = os.path.join(output_directory, output_file)

        # in this way io don't lose the activity already done 
        if not os.path.exists(output_path):
            # execute nmap
            command = ["nmap", ip.strip(), '-sV', '-T4', '-Pn']
            try:
                with open(output_path, "w") as output_file:
                    console.print(f'[INFO] Starting nmap scan on {ip}\n', style='info')
                    subprocess.run(command, stdout=output_file, stderr=subprocess.STDOUT, check=False)
                console.print(f"[SUCCESS] nmap scan completed for {ip.strip()}. Results saved in {output_path}", style='success')
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] nmap error while scanning {ip.strip()}: {e}", style='error')
            except Exception as e:
                console.print(f"[ERROR] nmap error occurred: {e}", style='error')
        else:
            console.print(f"[SUCCESS] Nmap Output file {output_path} for {ip} already present, maybe from previous scan", style='success')





def scan_with_dirb(domains):
    script_directory = os.path.dirname(__file__)
    for domain in domains:
        url = 'https://www.'+domain+'/'

        if domain == ORIGINAL_DOMAIN:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "web_info_gathering", "dirb")
        else:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan","subdomains", "web_info_gathering", "dirb")

        output_file = f"{domain}.txt"
        output_path = os.path.join(output_directory, output_file)

        #to don't lose the activities already done
        if not os.path.exists(output_path):
            try:

                os.makedirs(output_directory, exist_ok=True)
                command = ['dirb', url, '-r', '-o', output_path]

            
                console.print(f'[INFO] Starting dirb scan on {domain}\n', style='info')
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                errors = process.stderr.read()
                if errors:
                    console.print(f"error executing dirb {url} -r: {errors}", style="error")
                else:
                    console.print(f"[SUCCESS] dirb scan completed for {url}. Results saved in {output_path}", style="success")
            except Exception as e:
                console.print(f"error on executing dirb {url} -r: {e}", style="error")
        else:
            console.print(f"[SUCCESS] Dirb Output file {output_path} for {domain} already present, maybe from previous scan", style='success')


def scan_with_nikto(domains):
    script_directory = os.path.dirname(__file__)
    for domain in domains:
        url = 'https://'+domain+'/'

        if domain == ORIGINAL_DOMAIN:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "web_info_gathering", "nikto")
        else:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan","subdomains", "web_info_gathering", "nikto")

        output_file = f"{domain}.txt"
        output_path = os.path.join(output_directory, output_file)

        #to don't lose the activities already done
        if not os.path.exists(output_path):
            try:

                os.makedirs(output_directory, exist_ok=True)
                command = ['nikto', '-host', url, '-o', output_path]

            
                console.print(f'[INFO] Starting nikto scan on {domain}\n', style='info')
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                errors = process.stderr.read()
                if errors:
                    console.print(f"error executing nikto {url} -r: {errors}", style="error")
                else:
                    console.print(f"[SUCCESS] nikto scan completed for {url}. Results saved in {output_path}", style="success")
            except Exception as e:
                console.print(f"error on executing nikto {url} -r: {e}", style="error")
        else:
            console.print(f"[SUCCESS] Nikto Output file {output_path} for {domain} already present, maybe from previous scan", style='success')



def scan_with_nmap_domains(unique_domains):
    script_directory = os.path.dirname(__file__)
    

    for domain in unique_domains:
        console.print(domain)
        if domain == ORIGINAL_DOMAIN:
            output_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "network_info_gathering", "nmap")
        else:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan","subdomains", "network_info_gathering", "nmap")
        
        # check if the output directory exists, if not create it
        os.makedirs(output_directory, exist_ok=True)
        output_file = f"{domain.strip()}.txt"
        output_path = os.path.join(output_directory, output_file)

        #to don't lose the activities already done
        if not os.path.exists(output_path):
            # execute nmap
            command = ["nmap", domain.strip(), '-sV', '-T4', '-Pn']
            try:
                with open(output_path, "w") as output_file:
                    console.print(f'[INFO] Starting nmap scan on {domain}\n', style='info')
                    subprocess.run(command, stdout=output_file, stderr=subprocess.STDOUT, check=False)
                console.print(f"[SUCCESS] nmap scan completed for {domain.strip()}. Results saved in {output_path}", style='success')
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] nmap error while scanning {domain.strip()}: {e}", style='error')
            except Exception as e:
                console.print(f"[ERROR] nmap error occurred: {e}", style='error')
        else:
            console.print(f"[SUCCESS] Nmap Output file {output_path} for {domain} already present, maybe from previous scan", style='success')

            

def scan_with_joomla(domains):
    script_directory = os.path.dirname(__file__)
    for domain in domains:
        url = 'https://'+domain+'/'

        if domain == ORIGINAL_DOMAIN:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "web_info_gathering", "joomscan")
        else:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan","subdomains", "web_info_gathering", "joomscan")

        output_file = f"{domain}.txt"
        output_path = os.path.join(output_directory, output_file)
        
        #to don't lose the activities already done
        if not os.path.exists(output_path):
            try:
                joomscan_path = os.path.join(script_directory, "joomscan", "joomscan.pl")

                os.makedirs(output_directory, exist_ok=True)
                command = ['perl', joomscan_path, '-u', url]

                with open(output_path, "w") as f:
                    console.print(f'[INFO] Starting joomla scan on {domain}\n', style='info')
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for line in process.stdout:
                        filtered_line = remove_non_printable(line)
                        f.write(filtered_line)

                errors = process.stderr.read()
                if errors:
                    console.print(f"error executing perl joomscan -t {url}: {errors}", style="error")
                else:
                    console.print(f"[SUCCESS] joomla scan completed for {url}. Results saved in {output_path}", style="success")
            except Exception as e:
                console.print(f"error on executing joomscan -t {url}: {e}", style="error")
        else:
            console.print(f"[SUCCESS] Joomla Output file {output_path} for {domain} already present, maybe from previous scan", style='success')



def scan_with_nuclei(domains):
    script_directory = os.path.dirname(__file__)

    for domain in domains:
        if domain == ORIGINAL_DOMAIN:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan", f"{ORIGINAL_DOMAIN}", "web_info_gathering", "nuclei")
        else:
            output_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan", "subdomains" "web_info_gathering", "nuclei")

        output_file = f"{domain}.txt"
        output_path = os.path.join(output_directory, output_file)

        nuclei_path = os.path.join(script_directory, "nuclei", "nuclei")
        nuclei_tempaltes_path = os.path.join(script_directory, "nuclei", "nuclei-templates")

        command = [nuclei_path, "-u", domain, "-t", nuclei_tempaltes_path, "-rl", "10", "-o", output_path]
        
        #to don't lose the activities already done
        if not os.path.exists(output_path):
            try:
                os.makedirs(output_directory, exist_ok=True)
                with open(output_path, "w") as output_file:
                    console.print(f'[INFO] Starting nuclei scan on {domain}\n', style='info')
                    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                console.print(f'[SUCCESS] nuclei scan completed for {domain}. Results saved in {output_path}', style="success")
            except subprocess.CalledProcessError as e:
                console.print(f"[Error] nuclei error occurred while scanning {domain}: {e}")
            except Exception as e:
                console.print(f"[Error] nuclei error occurred while scanning {domain}: {e}")
        else:
            console.print(f"[SUCCESS] Nuclei Output file {output_path} for {domain} already present, maybe from previous scan", style='success')

        
def create_joomla_report(joomla_dir):
    markdown = '## Joomscan report\n\n\nThis is the result of the Joomscan activity.\n **Here you can find only the relevant information** \n **Remeber:** <span style="color:red; font-weight: bold;"> when the text is red, something interesting is found </span>  '
    if not os.path.isdir(joomla_dir):
        return markdown
    lines = ''
    is_real_content = False
    for filename in os.listdir(joomla_dir):
        filepath = os.path.join(joomla_dir, filename)
        name, _ = os.path.splitext(filename)
        if os.path.isfile(filepath):
            markdown += f'\n### Joomscan for {name}'
            with open(filepath, 'r', encoding='utf-8') as file:
                 for line in file:
                    if '[+] FireWall Detector' in line:
                        is_real_content=True
                    if "not found" not in line.lower() and "not detected" not in line.lower() and "not vulnerable" not in line.lower() and "reports/" not in line.lower():
                        if is_real_content:
                            if '[++]' in line.lower():
                                parsed_line = '\n <span style="color:red; font-weight: bold;">' + line.strip() + '</span> \n'
                            elif '[++]' not in line.lower() and '[+]' not in line.lower() and not (line== '' or line=='\n'):
                                if line.startswith('http'):
                                    parsed_line = f'\n - [{line.strip()}]({line.strip()}) \n'
                                else:
                                    parsed_line = '\n - ' + line.strip()+' \n'
                            else: 
                                parsed_line = '\n ' + line.strip()+' \n'

                            lines+=parsed_line
    lines+='\n\n\n\n'
    markdown+=lines
    return markdown


def create_dirb_report(dirb_dir):
    markdown = '## Dirb report\n\n\nThis is the result of the Dirb activity.\n **Here you can find only the relevant information** \n **Remeber:** <span style="color:red; font-weight: bold;"> Only responses with code 200 are reported here </span>  '
    print(dirb_dir)
    if not os.path.isdir(dirb_dir):
        return markdown
    lines = ''
    is_real_content = False
    for filename in os.listdir(dirb_dir):
        filepath = os.path.join(dirb_dir, filename)
        name, _ = os.path.splitext(filename)
        if os.path.isfile(filepath):
            markdown += f'\n### Dirb scan for {name}'
            with open(filepath, 'r', encoding='utf-8') as file:
                 for line in file:
                    if '+' in line:
                        is_real_content=True
                        print(line)
                    if "CODE:200" in line:
                        splitted = line.split()

                        if is_real_content:
                            parsed_line = f'\n- [{splitted[1]}]({splitted[1]}) \t\t\t\t\t\t\t\t {splitted[2]} \n'
                            lines+=parsed_line
    lines+='\n\n\n\n'
    markdown+=lines
    return markdown


                


def create_main_domain_report():
    script_directory = os.path.dirname(__file__)
    web_joomla_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "web_info_gathering", "joomscan")
    web_nikto_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "web_info_gathering", "nikto")
    web_dirb_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan", f"{ORIGINAL_DOMAIN}","web_info_gathering", "dirb")
    web_nuclei_directory = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan", f"{ORIGINAL_DOMAIN}", "web_info_gathering", "nuclei")
    network_nmap_directory = os.path.join(script_directory, "output", f"{ORIGINAL_DOMAIN}_scan",f"{ORIGINAL_DOMAIN}", "network_info_gathering", "nmap")

    markdown_title = f"""
                    (        )  (    (    (         
               (    )\ )  ( /(  )\ ) )\ ) )\ )      
               )\  (()/(  )\())(()/((()/((()/( (    
             (((_)  /(_))((_)\  /(_))/(_))/(_)))\   
             )\___ (_)) __ ((_)(_)) (_)) (_)) ((_)  
            ((/ __|| _ \\ \ / / | _ \|_ _|| _ \| __| 
             | (__ |   / \ V / |  _/ | | |  _/| _|  
              \___||_|_\  |_|  |_|  |___||_|  |___|                                         
"""
    
    markdown_title += f"# Report for domain {ORIGINAL_DOMAIN}\n\n\n"

    joomla_report_markdown = create_joomla_report(web_joomla_directory)
    dirb_report_markdown = create_dirb_report(web_dirb_directory)

    final_report_path = os.path.join(script_directory, "output",f"{ORIGINAL_DOMAIN}_scan", f"final_report")
    os.makedirs(final_report_path, exist_ok=True)

    final_report_name = 'final_report_main_domain.pdf'

    final_report = os.path.join(final_report_path, final_report_name)

    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(markdown_title, toc=False))
    pdf.add_section(Section(joomla_report_markdown, toc=False))
    pdf.add_section(Section(dirb_report_markdown, toc=False))

    pdf.save(final_report)














@app.command()
def main(domain: str = typer.Option('', "--domain", "-d", help="Domain to scan (REQUIRED)"), all_subdomains: bool = typer.Option(False, "--all-subdomains", "-a", help="Process all subdomains (default: False)")):
    banner()
    if '' == domain:
        return
    global ORIGINAL_DOMAIN

    ORIGINAL_DOMAIN = domain

    status = console.status(f"[{spinner_style}][STEP 1] Preliminary setup -> I'm scanning subdomains...", spinner_style=spinner_style)
    with status:
        output_filename=f"subdomains_with_IPs_{domain}.txt"
        (all_ip_addresses, domains) = process_domain(domain, output_filename, all_subdomains)
        unique_ip_addresses=remove_duplicates_and_save(all_ip_addresses)
        sort_file(output_filename)
        binded_ips = bind_unique_IPs_to_domains(output_filename)

        #console.print(binded_ips)
    
    status.stop()

    status = console.status(f"[{spinner_style}][Step 2 - Nuclei, Joomscan, Nmap, Dirb] I'm executing my activities in parallel... You will be noticed when the activities are done. Let me cook bro 🍝🍝", spinner_style=spinner_style)
    with status:
        """joomla_thread = threading.Thread(target=scan_with_joomla, args=(domains,))
        joomla_thread.start()
        joomla_thread.join()"""
        """nmap_thread = threading.Thread(target=scan_with_nmap_IPs, args=(unique_ip_addresses,))
        
        dirb_thread = threading.Thread(target=scan_with_dirb, args=(domains,))
        nikto_thread = threading.Thread(target=scan_with_nikto, args=(domains,))
        nuclei_thread = threading.Thread(target=scan_with_nuclei, args=(domains,))

        nmap_thread.start()
        joomla_thread.start()
        nuclei_thread.start()
        dirb_thread.start()
        nikto_thread.start()

        nmap_thread.join()
        joomla_thread.join()
        nuclei_thread.join()
        dirb_thread.join()
        nikto_thread.join()"""

        create_main_domain_report()

    status.stop()

if __name__ == "__main__":
    app()