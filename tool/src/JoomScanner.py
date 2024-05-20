import os
import string
import subprocess

class JoomScanner:
    script_directory = os.path.dirname(__file__)
    script_directory = os.path.dirname(script_directory)

    def __init__(self, original_domain, domains, console):
        self.original_domain = original_domain
        self.domains = domains
        self.console = console

    def remove_non_printable(self, text):
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

    def scan_with_joomla(self):
        for domain in self.domains:
            url = 'https://' + domain + '/'
            
            if domain == self.original_domain:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", f"{self.original_domain}", "web_info_gathering", "joomscan")
            else:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", "subdomains", "web_info_gathering", "joomscan")

            output_file = f"{domain}.txt"
            output_path = os.path.join(output_directory, output_file)
            
            if not os.path.exists(output_path):
                try:
                    joomscan_path = os.path.join(self.script_directory, "joomscan", "joomscan.pl")
                    os.makedirs(output_directory, exist_ok=True)
                    command = ['perl', joomscan_path, '-u', url]

                    with open(output_path, "w") as f:
                        self.console.print(f'[INFO] Starting joomla scan on {domain}\n', style='info')
                        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        for line in process.stdout:
                            filtered_line = self.remove_non_printable(line)
                            f.write(filtered_line)

                    errors = process.stderr.read()
                    if errors:
                        self.console.print(f"error executing perl joomscan -t {url}: {errors}", style="error")
                    else:
                        self.console.print(f"[SUCCESS] joomla scan completed for {url}. Results saved in {output_path}", style="success")
                except Exception as e:
                    self.console.print(f"error on executing joomscan -t {url}: {e}", style="error")
            else:
                self.console.print(f"[SUCCESS] Joomla Output file {output_path} for {domain} already present, maybe from previous scan", style='success')

