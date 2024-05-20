import os
from markdown_pdf import MarkdownPdf
from markdown_pdf import Section



class ReportGenerator():

    def __init__(self, original_domain, binded_ips, all_subdomains) -> None:
        self.original_domain = original_domain
        self.binded_ips = binded_ips
        self.all_subdomains = all_subdomains
        
    def create_joomla_report(self, joomla_dir):
        markdown = '# Joomscan report\n\n\nThis is the result of the Joomscan activity.\n **Here you can find only the relevant information** \n **Remeber:** <span style="color:red; font-weight: bold;"> when the text is red, something interesting is found </span>  '
        if not os.path.isdir(joomla_dir):
            return markdown
        lines = ''
        is_real_content = False
        for filename in os.listdir(joomla_dir):
            filepath = os.path.join(joomla_dir, filename)
            name, _ = os.path.splitext(filename)
            if os.path.isfile(filepath):
                is_real_content = False
                internal_lines = f'\n### Joomscan for {name}\n\n'
                with open(filepath, 'r', encoding='utf-8') as file:
                    for line in file:
                        if '[+] FireWall Detector' in line:
                            is_real_content=True
                        if "not found" not in line.lower() and "not detected" not in line.lower() and "not vulnerable" not in line.lower() and "reports/" not in line.lower():
                            if is_real_content:
                                if '[++]' in line.lower() and "ver 404" not in line:
                                    parsed_line = '\n <span style="color:red; font-weight: bold;">' + line.strip() + '</span> \n'
                                elif '[++]' not in line.lower() and '[+]' not in line.lower() and not (line== '' or line=='\n'):
                                    if line.startswith('http'):
                                        parsed_line = f'\n - [{line.strip()}]({line.strip()}) \n'
                                    else:
                                        parsed_line = '\n - ' + line.strip()+' \n'
                                else: 
                                    parsed_line = '\n ' + line.strip()+' \n'

                                internal_lines+=parsed_line
                if 'the target is not alive' in internal_lines.lower() or '<span style="color:red; font-weight: bold;">' not in internal_lines.lower():
                    internal_lines=''
                
                lines+=internal_lines+'\n\n\n\n'
        markdown+=lines
        return markdown


    def create_dirb_report(self, dirb_dir):
        markdown = '# Dirb report\n\n\nThis is the result of the Dirb activity.\n **Here you can find only the relevant information** \n **Remeber:** <span style="color:red; font-weight: bold;"> Only responses with code 200 are reported here </span>  '
        print(dirb_dir)
        if not os.path.isdir(dirb_dir):
            return markdown
        lines = ''
        for filename in os.listdir(dirb_dir):
            is_real_content = False
            content=0

            filepath = os.path.join(dirb_dir, filename)
            name, _ = os.path.splitext(filename)
            if os.path.isfile(filepath):
                internal_lines = f'\n### Dirb scan for {name}'
                with open(filepath, 'r', encoding='utf-8') as file:
                    for line in file:
                        if '+' in line:
                            is_real_content=True
                        if "CODE:200" in line:
                            splitted = line.split()

                            if is_real_content:
                                content+=1
                                parsed_line = f'\n- [{splitted[1]}]({splitted[1]}) \t\t\t\t\t\t\t\t {splitted[2]} \n'
                                internal_lines+=parsed_line
            
            internal_lines+='\n\n\n\n'
            if content==0:
                internal_lines=''
            lines+=internal_lines
            
        markdown+=lines
        return markdown

    def create_nikto_report(self, nikto_dir):
        markdown = '# Nikto report\n\n\nThis is the result of the Nikto activity.\n **Here you can find only the relevant information** \n **Remeber:** <span style="color:red; font-weight: bold;"> some discoveries could be false positive, since nikto checks the response code for some vulnerabilities -> example XSS </span> \n\n\n'
        print(nikto_dir)
        if not os.path.isdir(nikto_dir):
            return markdown
        lines = ''
        for filename in os.listdir(nikto_dir):
            is_real_content = False

            content=0
            filepath = os.path.join(nikto_dir, filename)
            name, _ = os.path.splitext(filename)
            if os.path.isfile(filepath):
                internal_lines = f'\n### Nikto scan for {name}\n\n'
                with open(filepath, 'r', encoding='utf-8') as file:
                    for line in file:
                        if '+' in line:
                            is_real_content=True
                        if is_real_content:
                            internal_lines+=line
                            content+=1

            internal_lines+='\n\n\n\n'
            if content==0:
                internal_lines=''
            
            lines+=internal_lines

        markdown+=lines
        return markdown

    def create_nuclei_report(self, nuclei_dir):
        markdown = f'# Nuclei report\n\n\nThis is the result of the Nuclei activity.\n **Here you can find only the relevant information** \n\n\n'\
        '**Remeber:**\n'\
        '- <span style="color:green; font-weight: bold; font-size: 12px;">Green is used for low impact vulnerabilities  </span> \n\n\n'\
        '- <span style="color:orange; font-weight: bold; font-size: 12px;">Orange is used for medium impact vulnerabilities  </span> \n\n\n'\
        '- <span style="color:red; font-weight: bold; font-size: 12px;">Red is used for high impact vulnerabilities  </span> \n\n\n'
        print(nuclei_dir)
        if not os.path.isdir(nuclei_dir):
            return markdown
        lines = ''
        for filename in os.listdir(nuclei_dir):
            filepath = os.path.join(nuclei_dir, filename)
            name, _ = os.path.splitext(filename)
            if os.path.isfile(filepath):
                content = 0
                internal_lines= f'\n### Nuclei scan for {name}\n\n'
                with open(filepath, 'r', encoding='utf-8') as file:
                    for line in file:
                        content+=1
                        if '[info]' in line:
                            internal_lines+=f'\n- {line}\n'
                        if '[low]' in line:
                            internal_lines+=f'\n- <span style="color:green; font-weight: bold;font-size: 12px;">{line}</span>\n'
                        if '[medium]' in line:
                            internal_lines+=f'\n- <span style="color:orange; font-weight: bold;font-size: 12px;">{line}</span>\n'
                        if '[high]' in line:
                            internal_lines+=f'\n- <span style="color:red; font-weight: bold;font-size: 12px;">{line}</span>\n'
                        
                internal_lines+='\n\n\n\n'
                if content==0:
                    internal_lines=''
                lines+=internal_lines

        markdown+=lines
        return markdown


    def create_nmap_report(self, nmap_dir):
        markdown = f'# Nmap report\n\n\nThis is the result of the Nmap activity.\n **Here you can find only the relevant information** \n\n\n'
        print(nmap_dir)
        if not os.path.isdir(nmap_dir):
            return markdown
        lines = ''
        is_real_content = False
        for filename in os.listdir(nmap_dir):
            is_real_content = False


            filepath = os.path.join(nmap_dir, filename)
            name, _ = os.path.splitext(filename)
            if os.path.isfile(filepath):
                domains_list = []
                if self.binded_ips[name]:
                    domains_list=self.binded_ips[name]
                content = 0
                
                internal_file_lines = f'\n### Nmap scan for {name} : {domains_list}\n\n'
                internal_file_lines+='\n\n``` '
                with open(filepath, 'r', encoding='utf-8') as file:
                    for line in file:
                        if 'PORT' in line:
                            internal_file_lines +=f'{line}'
                            is_real_content=True
                        if is_real_content:
                            if 'unrecognized' not in line:
                                internal_file_lines +=f'{line}'
                                content+=1
                                print(name, line)
                            else:
                                internal_file_lines +=f'\n{line}'
                                content+=1

                    

                    
                internal_file_lines+='```\n'
                if content == 0:
                    internal_file_lines = ''
                
                lines += internal_file_lines
                            
                        
        lines+='\n\n\n\n'
        markdown+=lines
        return markdown



                    


    def create_main_domain_report(self):
        script_directory = os.path.dirname(__file__)
        script_directory = os.path.dirname(script_directory)
        web_joomla_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan",f"{self.original_domain}", "web_info_gathering", "joomscan")
        web_nikto_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan",f"{self.original_domain}", "web_info_gathering", "nikto")
        web_dirb_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan", f"{self.original_domain}","web_info_gathering", "dirb")
        web_nuclei_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan", f"{self.original_domain}", "web_info_gathering", "nuclei")
        network_nmap_directory = os.path.join(script_directory, "output", f"{self.original_domain}_scan",f"{self.original_domain}", "network_info_gathering", "nmap")
        cry_banner = f"""
              (        )  (    (    (         
         (    )\ )  ( /(  )\ ) )\ ) )\ )      
         )\  (()/(  )\())(()/((()/((()/( (    
         (((_)  /(_))((_)\  /(_))/(_))/(_)))\   
         )\___ (_)) __ ((_)(_)) (_)) (_)) ((_)  
       ((/ __|| _ \ \ \ / /| _ \|_ _|| _ \| __| 
        | (__ |   /  \ V / |  _/ | | |  _/| _|  
         \___||_|_\   |_|  |_|  |___||_|  |___|

    """
        
        markdown_title = cry_banner+ f"\n# Report for domain {self.original_domain}\n\n\n"

        nmap_report_markdown = self.create_nmap_report(network_nmap_directory)
        joomla_report_markdown = self.create_joomla_report(web_joomla_directory)
        dirb_report_markdown = self.create_dirb_report(web_dirb_directory)
        nikto_report_markdown = self.create_nikto_report(web_nikto_directory)
        nuclei_report_markdown = self.create_nuclei_report(web_nuclei_directory)


        final_report_path = os.path.join(script_directory, "output",f"{self.original_domain}_scan", f"final_reports")
        os.makedirs(final_report_path, exist_ok=True)

        final_report_name = 'final_report_main_domain.pdf'

        final_report = os.path.join(final_report_path, final_report_name)

        pdf = MarkdownPdf(toc_level=2)
        pdf.add_section(Section(markdown_title, toc=False))
        pdf.add_section(Section(nmap_report_markdown, toc=False))

        pdf.add_section(Section(joomla_report_markdown, toc=False))
        pdf.add_section(Section(nikto_report_markdown, toc=False))
        pdf.add_section(Section(nuclei_report_markdown, toc=False))

        pdf.add_section(Section(dirb_report_markdown, toc=False))

        pdf.save(final_report)

        if self.all_subdomains:
            web_joomla_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan", "subdomains", "web_info_gathering", "joomscan")
            web_nikto_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan", "subdomains","web_info_gathering", "nikto")
            web_dirb_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan","subdomains","web_info_gathering", "dirb")
            web_nuclei_directory = os.path.join(script_directory, "output",f"{self.original_domain}_scan","subdomains", "web_info_gathering", "nuclei")
            network_nmap_directory = os.path.join(script_directory, "output", f"{self.original_domain}_scan", "subdomains", "network_info_gathering", "nmap")
            
        
            markdown_title = cry_banner + f"\n# Report for subdomains of {self.original_domain}\n\n\n"

            nmap_report_markdown = self.create_nmap_report(network_nmap_directory)
            joomla_report_markdown = self.create_joomla_report(web_joomla_directory)
            dirb_report_markdown = self.create_dirb_report(web_dirb_directory)
            nikto_report_markdown = self.create_nikto_report(web_nikto_directory)
            nuclei_report_markdown = self.create_nuclei_report(web_nuclei_directory)

            final_report_name = 'final_report_subdomains.pdf'

            final_report = os.path.join(final_report_path, final_report_name)

            pdf = MarkdownPdf(toc_level=2)
            pdf.add_section(Section(markdown_title, toc=False))
            pdf.add_section(Section(nmap_report_markdown, toc=False))

            pdf.add_section(Section(joomla_report_markdown, toc=False))
            pdf.add_section(Section(nikto_report_markdown, toc=False))
            pdf.add_section(Section(nuclei_report_markdown, toc=False))

            pdf.add_section(Section(dirb_report_markdown, toc=False))

            pdf.save(final_report)









