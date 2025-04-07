import os
import subprocess

class FuffScanner:
    script_directory = os.path.dirname(__file__)
    script_directory = os.path.dirname(script_directory)


    def __init__(self, original_domain, console, domains):
        self.original_domain = original_domain
        self.console = console
        self.domains = domains

    def scan_with_ffuf(self):
        for domain in self.domains:
            url = 'https://' + domain + '/'

            response_size_to_avoid = '0'
            response_code_to_avoid = '403'

            extensions = ''


            if domain == self.original_domain:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", f"{self.original_domain}", "web_info_gathering", "ffuf")
            else:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", "subdomains", "web_info_gathering", "ffuf")

            output_file = f"{domain}.txt"
            output_path = os.path.join(output_directory, output_file)

            #to don't lose the activities already done
            if not os.path.exists(output_path):
                try:
                    os.makedirs(output_directory, exist_ok=True)
                    command = ['ffuf', '-u', f'{url}FUZZ', '-w','/snap/seclists/current/Discovery/Web-Content/directory-list-2.3-small.txt', '-fs', response_size_to_avoid,
                                '-fc', response_code_to_avoid, '-o', output_path, '-of', 'csv']

                    
                    print(' '.join(command))

                    self.console.print(f'[INFO] Starting ffuf scan on {domain}\n', style='info')
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    stderr_output = process.stderr.read()
                    if stderr_output:
                        self.console.print(f"[ERROR] ffuf error output for {domain}:\n{stderr_output}", style="error")
                        
                   
                    self.console.print(f"[SUCCESS] ffuf scan completed for {url}. Results saved in {output_path}", style="success")
                except Exception as e:
                    self.console.print(f"error on executing ffuf {url} -r: {e}", style="error")
            else:
                self.console.print(f"[SUCCESS] ffuf Output file {output_path} for {domain} already present, maybe from previous scan", style='success')
