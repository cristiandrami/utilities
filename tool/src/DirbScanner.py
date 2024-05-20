import os
import subprocess

class DirbScanner:
    script_directory = os.path.dirname(__file__)
    script_directory = os.path.dirname(script_directory)


    def __init__(self, original_domain, console, domains):
        self.original_domain = original_domain
        self.console = console
        self.domains = domains

    def scan_with_dirb(self):
        for domain in self.domains:
            url = 'https://' + domain + '/'

            if domain == self.original_domain:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", f"{self.original_domain}", "web_info_gathering", "dirb")
            else:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", "subdomains", "web_info_gathering", "dirb")

            output_file = f"{domain}.txt"
            output_path = os.path.join(output_directory, output_file)

            #to don't lose the activities already done
            if not os.path.exists(output_path):
                try:
                    os.makedirs(output_directory, exist_ok=True)
                    command = ['dirb', url, '-r', '-f', '-o', output_path]

                    self.console.print(f'[INFO] Starting dirb scan on {domain}\n', style='info')
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    errors = process.stderr.read()
                    if errors:
                        self.console.print(f"error executing dirb {url} -r: {errors}", style="error")
                    else:
                        self.console.print(f"[SUCCESS] dirb scan completed for {url}. Results saved in {output_path}", style="success")
                except Exception as e:
                    self.console.print(f"error on executing dirb {url} -r: {e}", style="error")
            else:
                self.console.print(f"[SUCCESS] Dirb Output file {output_path} for {domain} already present, maybe from previous scan", style='success')
