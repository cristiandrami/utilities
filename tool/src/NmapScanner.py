import os
import subprocess

class NmapScanner:
    script_directory = os.path.dirname(__file__)
    script_directory = os.path.dirname(script_directory)

    def __init__(self, original_domain, original_ip, unique_ips,  console):
        self.original_domain = original_domain
        self.console = console
        self.unique_ips = unique_ips
        self.original_ip= original_ip
        self.unique_domains = '' #TODO

    def scan_with_nmap_IPs(self):
        for ip in self.unique_ips:
            if ip == self.original_ip:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", f"{self.original_domain}", "network_info_gathering", "nmap")
            else:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", "subdomains", "network_info_gathering", "nmap")
            
            os.makedirs(output_directory, exist_ok=True)
            output_file = f"{ip.strip()}.txt"
            output_path = os.path.join(output_directory, output_file)

            if not os.path.exists(output_path):
                command = ["nmap", ip.strip(), '-sV', '-T4', '-Pn']
                try:
                    with open(output_path, "w") as output_file:
                        self.console.print(f'[INFO] Starting nmap scan on {ip}\n', style='info')
                        subprocess.run(command, stdout=output_file, stderr=subprocess.STDOUT, check=False)
                    self.console.print(f"[SUCCESS] nmap scan completed for {ip.strip()}. Results saved in {output_path}", style='success')
                except subprocess.CalledProcessError as e:
                    self.console.print(f"[ERROR] nmap error while scanning {ip.strip()}: {e}", style='error')
                except Exception as e:
                    self.console.print(f"[ERROR] nmap error occurred: {e}", style='error')
            else:
                self.console.print(f"[SUCCESS] Nmap Output file {output_path} for {ip} already present, maybe from previous scan", style='success')


    def scan_with_nmap_domains(self):    

        for domain in self.unique_domains:
            if domain == self.original_domain:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan",f"{self.original_domain}", "network_info_gathering", "nmap")
            else:
                output_directory = os.path.join(self.script_directory, "output",f"{self.original_domain}_scan","subdomains", "network_info_gathering", "nmap")
            
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
                        self.console.print(f'[INFO] Starting nmap scan on {domain}\n', style='info')
                        subprocess.run(command, stdout=output_file, stderr=subprocess.STDOUT, check=False)
                    self.console.print(f"[SUCCESS] nmap scan completed for {domain.strip()}. Results saved in {output_path}", style='success')
                except subprocess.CalledProcessError as e:
                    self.console.print(f"[ERROR] nmap error while scanning {domain.strip()}: {e}", style='error')
                except Exception as e:
                    self.console.print(f"[ERROR] nmap error occurred: {e}", style='error')
            else:
                self.console.print(f"[SUCCESS] Nmap Output file {output_path} for {domain} already present, maybe from previous scan", style='success')

