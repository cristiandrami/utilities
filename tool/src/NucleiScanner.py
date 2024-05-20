import os
import subprocess

class NucleiScanner:
    # src, but we want the root dir
    script_directory = os.path.dirname(__file__)
    #root dir
    script_directory = os.path.dirname(script_directory)

    nuclei_path = os.path.join(script_directory, "nuclei", "nuclei")
    nuclei_templates_path = os.path.join(script_directory, "nuclei", "nuclei-templates")

    def __init__(self, original_domain, domains,  console):
        self.original_domain = original_domain
        self.domains = domains
        self.console = console

    def scan_with_nuclei(self):
        for domain in self.domains:
            if domain == self.original_domain:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", f"{self.original_domain}", "web_info_gathering", "nuclei")
            else:
                output_directory = os.path.join(self.script_directory, "output", f"{self.original_domain}_scan", "subdomains", "web_info_gathering", "nuclei")

            output_file = f"{domain}.txt"
            output_path = os.path.join(output_directory, output_file)

            command = [self.nuclei_path, "-u", domain, "-t", self.nuclei_templates_path, "-rl", "10", "-o", output_path]

            #to don't lose the activities already done
            if not os.path.exists(output_path):
                try:
                    os.makedirs(output_directory, exist_ok=True)
                    with open(output_path, "w") as output_file:
                        self.console.print(f'[INFO] Starting nuclei scan on {domain}\n', style='info')
                        subprocess.run(command, stdout=output_file, stderr=subprocess.PIPE, text=True)
                    self.console.print(f'[SUCCESS] nuclei scan completed for {domain}. Results saved in {output_path}', style="success")
                except subprocess.CalledProcessError as e:
                    self.console.print(f"[Error] nuclei error occurred while scanning {domain}: {e}")
                except Exception as e:
                    self.console.print(f"[Error] nuclei error occurred while scanning {domain}: {e}")
            else:
                self.console.print(f"[SUCCESS] Nuclei Output file {output_path} for {domain} already present, maybe from previous scan", style='success')

