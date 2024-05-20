import os
import subprocess

class NiktoScanner:
    script_directory = os.path.dirname(__file__)
    script_directory = os.path.dirname(script_directory)

    def __init__(self, original_domain,domains, console):
        self.original_domain = original_domain
        self.domains = domains
        self.console = console

    def scan_with_nikto(self):
        for domain in self.domains:
            url = 'https://' + domain + '/'
            
            if domain == self.original_domain:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", f"{self.original_domain}", "web_info_gathering", "nikto")
            else:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", "subdomains", "web_info_gathering", "nikto")

            output_file = f"{domain}.txt"
            output_path = os.path.join(output_directory, output_file)
            
            if not os.path.exists(output_path):
                try:
                    os.makedirs(output_directory, exist_ok=True)
                    command = ['nikto', '-host', url, '-o', output_path]

                    self.console.print(f'[INFO] Starting nikto scan on {domain}\n', style='info')
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    errors = process.stderr.read()
                    if errors:
                        self.console.print(f"error executing nikto {url} -r: {errors}", style="error")
                    else:
                        self.console.print(f"[SUCCESS] nikto scan completed for {url}. Results saved in {output_path}", style="success")
                except Exception as e:
                    self.console.print(f"error on executing nikto {url} -r: {e}", style="error")
            else:
                self.console.print(f"[SUCCESS] Nikto Output file {output_path} for {domain} already present, maybe from previous scan", style='success')
