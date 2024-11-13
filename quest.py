import json
import shodan
import os
from pprint import pprint

# Function to save API key
def saveAPIKey(apiKey):
    with open('shodan_key.txt', 'w') as f:
        f.write(apiKey)

# Function to get saved API key
def getSavedAPIKey():
    if os.path.isfile('shodan_key.txt'):
        with open('shodan_key.txt', 'r') as f:
            return f.read().strip()
    return ''

# Function to validate the API key
def checkShodanAPIKey(apiKey):
    try:
        print('[⏳] Checking if the Shodan API key is valid...')
        api = shodan.Shodan(apiKey)
        api.search('0_0')
        print('[✔️] API Key Authentication: SUCCESS..!')
        saveAPIKey(apiKey)
        print('[📑] The API Key has been saved.\n')
        return apiKey
    except shodan.APIError as errorMessage:
        print(f'[🚫] Error: {errorMessage}. Please, try again.')
        exit()

# Load API key
SHODAN_API_KEY = getSavedAPIKey() or checkShodanAPIKey(input("Enter your Shodan API Key: "))
api = shodan.Shodan(SHODAN_API_KEY)

# Display Banner
def display_banner():
    print("""
░██████╗██╗░░██╗░█████╗░██████╗░░█████╗░███╗░░██╗  
██╔════╝██║░░██║██╔══██╗██╔══██╗██╔══██╗████╗░██║  
╚█████╗░███████║██║░░██║██║░░██║███████║██╔██╗██║  
░╚═══██╗██╔══██║██║░░██║██║░░██║██╔══██║██║╚████║  
██████╔╝██║░░██║╚█████╔╝██████╔╝██║░░██║██║░╚███║  
╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░╚═╝░░╚═╝╚═╝░░╚══╝  
""")

# Predefined search queries
search_queries = {
    "Cameras": "port:554 has_screenshot:true",  # Surveillance cameras using RTSP protocol with screenshots enabled, often exposing sensitive footage
    "SCADA Systems": "tag:SCADA",  # Systems related to Supervisory Control and Data Acquisition, used in industrial control, often vulnerable to attacks
    "MongoDB Databases": "product:MongoDB",  # MongoDB databases accessible over the internet, frequently misconfigured and exposed
    "FTP Servers": "port:21",  # File Transfer Protocol servers, commonly used for file sharing and transfer, vulnerable to brute-force and other attacks
    "ElasticSearch Instances": "product:ElasticSearch",  # ElasticSearch instances exposed to the internet, often vulnerable to remote code execution and data breaches
    "MySQL Databases": "port:3306",  # MySQL databases, often targeted by attackers with SQL injection or weak authentication
    "Remote Desktop (RDP)": "port:3389",  # Remote Desktop Protocol, a prime target for brute-force, credential stuffing, and remote exploitation
    "Industrial Control Systems": "tag:ics",  # Devices and systems for industrial control, often exposed to cyberattacks with potentially catastrophic consequences
    "Webcams": "has_screenshot:true",  # Web cameras with screenshot capability, revealing sensitive footage or private information
    "VNC Remote Control": "port:5900",  # VNC servers for remote control, often exposed to brute-force or weak password exploits
    "NAS Devices": "port:2049",  # Network-attached storage devices, vulnerable to unauthorized access and insecure file sharing
    "MikroTik Routers": "product:MikroTik",  # MikroTik routers, notorious for weak configurations and targeted by cybercriminals
    "APC UPS": "product:APC",  # APC Uninterruptible Power Supplies, often exposed without proper security configurations
    "Printers": "port:9100",  # Network printers, often exposed via port 9100, vulnerable to unauthorized access and exploitation
    "VoIP Systems": "port:5060",  # Voice over IP systems (SIP), vulnerable to exploits, fraud, and eavesdropping attacks
    "Microsoft SQL Servers": "port:1433",  # Microsoft SQL Servers, often exposed with weak or default credentials and unpatched vulnerabilities
    "Oracle Databases": "port:1521",  # Oracle databases, commonly targeted for SQL injection and unauthorized access
    "SNMP Devices": "port:161",  # Simple Network Management Protocol devices, vulnerable to information leakage and unauthorized control
    "PostgreSQL Databases": "port:5432",  # PostgreSQL databases, often exposed to remote access without adequate protection
    "Internet of Things (IoT) Devices": "tag:iot",  # IoT devices with weak or default credentials, vulnerable to remote exploits
    "Docker Instances": "product:Docker",  # Docker containers, frequently misconfigured and exposed to vulnerabilities like privilege escalation
    "Redis Databases": "product:Redis",  # Redis databases, vulnerable to remote exploitation due to lack of authentication in many cases
    "OpenSSH": "product:OpenSSH",  # OpenSSH servers, often targeted by attackers using weak keys or brute-force techniques
    "OpenVPN Servers": "port:1194",  # OpenVPN servers, vulnerable to weak encryption or configuration errors allowing exploitation
    "Firewalls": "tag:firewall",  # Firewalls, can have misconfigurations or unpatched vulnerabilities that allow bypass of security controls
    "Telnet Servers": "port:23",  # Telnet servers, inherently insecure and vulnerable to attacks due to lack of encryption and weak authentication
    "Apache Servers": "product:Apache",  # Apache web servers, vulnerable to various misconfigurations, outdated versions, and known CVEs
    "Nginx Servers": "product:Nginx",  # Nginx servers, vulnerable to misconfigurations and exploits like injection attacks and server disclosure
    "Bash Servers": "product:Bash",  # Servers with Bash access, vulnerable to specific CVEs like Shellshock, allowing arbitrary code execution

    # Additional SCADA and industrial control system-specific queries
    "SCADA Systems - Vulnerable": "tag:SCADA vuln:*",  # SCADA systems exposed to known vulnerabilities
    "PLC Devices": "tag:PLC",  # Programmable Logic Controllers used in industrial control, often targeted by attackers
    "SCADA Remote Access": "port:502",  # SCADA systems exposed over Modbus (commonly port 502), often vulnerable to unauthorized remote access
    "HMI Systems": "tag:HMI",  # Human-Machine Interface systems, often part of SCADA networks, vulnerable to attacks
    "Industrial IoT (IIoT)": "tag:iiot",  # Industrial Internet of Things devices, often exposed and vulnerable to cyberattacks
    "Industrial Control Systems (ICS) Remote": "port:47808",  # Remote access points to ICS systems, often unsecured and vulnerable to attacks
    "HVAC Systems": "port:443 has_screenshot:true",  # Heating, Ventilation, and Air Conditioning systems often exposed with sensitive access
    "CCTV Systems": "port:80 has_screenshot:true",  # Internet-exposed CCTV cameras often misconfigured and exposed to external access
    "Modbus Devices": "port:502",  # Modbus protocol devices commonly used in industrial control and vulnerable to various attacks
    "Siemens S7 PLC": "product:Siemens S7",  # Siemens S7 PLC systems, commonly used in SCADA, exposed with misconfigurations
    "SCADA Admin Access": "port:8080 admin",  # Exposed SCADA admin access, often targeted for unauthorized control
    "Remote SCADA Interfaces": "port:443 product:SCADA",  # SCADA systems exposed on HTTPS port (443), potentially misconfigured and vulnerable
    "Industrial Ethernet Devices": "port:2000",  # Industrial Ethernet devices exposed with weak security configurations
    "Industrial Network Bridges": "port:2000 tag:ics",  # Network bridges for ICS systems, exposed with security flaws
    "Energy Management Systems": "tag:EMS",  # Systems for managing energy in industrial settings, often vulnerable to breaches
    "DCS Systems (Distributed Control Systems)": "tag:DCS",  # Distributed Control Systems used in manufacturing and industry, often exposed and vulnerable
    "Water Treatment Systems": "tag:water",  # Industrial water treatment systems, potentially exposing sensitive control data
    "SCADA Vulnerability CVE-2016-1102": "vuln:CVE-2016-1102",  # Known vulnerability in SCADA systems that can lead to unauthorized access
    "SCADA Vulnerability CVE-2015-3936": "vuln:CVE-2015-3936",  # Vulnerability in SCADA systems allowing attackers to gain unauthorized access
    "SCADA Vulnerability CVE-2019-18935": "vuln:CVE-2019-18935",  # Known SCADA vulnerability that could allow remote exploitation
}


# Predefined vulnerability search examples
vuln_queries = [
    "vuln:CVE-2020-5902 - F5 BIG-IP iControl vulnerability",
    "vuln:CVE-2019-19781 - Citrix ADC/RD Gateway vulnerability",
    "vuln:CVE-2018-8174 - Microsoft Internet Explorer vulnerability",
    "vuln:CVE-2017-5638 - Apache Struts vulnerability",
    "vuln:CVE-2020-3452 - Cisco ASA SSL VPN vulnerability",
    "vuln:CVE-2021-26855 - Microsoft Exchange Server vulnerability",
    "vuln:CVE-2021-21972 - VMware vCenter Server vulnerability",
    "vuln:CVE-2014-0160 - Heartbleed vulnerability",
    "vuln:CVE-2020-1472 - Netlogon vulnerability",
    "vuln:CVE-2019-0708 - BlueKeep vulnerability",
    "vuln:CVE-2022-1388 - F5 BIG-IP vulnerability",
    "vuln:CVE-2023-23397 - Microsoft Outlook vulnerability",
    "vuln:CVE-2022-22965 - Spring4Shell vulnerability",
    "vuln:CVE-2023-28771 - Citrix vulnerability",
    "vuln:CVE-2024-12345 - Sample CVE for testing",
    "vuln:CVE-2023-0045 - Android System WebView vulnerability",
    "vuln:CVE-2023-0472 - Apache Solr vulnerability",
    "vuln:CVE-2024-0017 - OpenSSL vulnerability",
    "vuln:CVE-2022-1292 - Atlassian Confluence vulnerability",
    "vuln:CVE-2022-22965 - Spring Framework vulnerability",
    #"vuln:CVE-2020-5902", "vuln:CVE-2019-19781", "vuln:CVE-2018-8174", "vuln:CVE-2017-5638",
    #"vuln:CVE-2020-3452", "vuln:CVE-2021-26855", "vuln:CVE-2021-21972", "vuln:CVE-2014-0160",
    #"vuln:CVE-2020-1472", "vuln:CVE-2019-0708", "vuln:CVE-2022-1388", "vuln:CVE-2023-23397",
    #"vuln:CVE-2022-22965", "vuln:CVE-2023-28771", "vuln:CVE-2024-12345", # Add more recent and critical vulnerabilities here
    # Additional CVEs from 2022, 2023, 2024
]

# Function for search and output
def search_shodan(query, file_name):
    try:
        results = api.search(query)
        print(f"Results found: {results['total']}")
        with open(file_name, 'a') as f:
            for result in results['matches']:
                pprint(result, stream=f)
                f.write('\n---\n')
        print(f"Results saved to {file_name}")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")

# Custom search submenu
def custom_search_menu(file_name):
    while True:
        print("\n--- Custom Search Menu ---")
        print("1. Banner Search\n2. IP Search\n3. Service Port\n4. Vulnerability\n5. Operating System")
        print("6. Location\n7. HTTP Header\n8. Protocol/Product\n9. Default Password\n10. Industrial Control Systems")
        print("11. City\n12. Firewall\n13. Telnet\n14. Go Back to Main Menu")

        choice = int(input("Choose an option: "))
        if choice == 1:
            query = input("Enter banner search query: ")
            search_shodan(query, file_name)
        elif choice == 2:
            ip = input("Enter IP address: ")
            search_shodan(f"ip:{ip}", file_name)
        elif choice == 3:
            service = input("Enter service port (e.g., 80, 443): ")
            search_shodan(f"port:{service}", file_name)
        elif choice == 4:
            vuln = input("Enter vulnerability keyword (e.g., CVE ID): ")
            search_shodan(f"vuln:{vuln}", file_name)
        elif choice == 5:
            os_name = input("Enter operating system name (e.g., Windows, Linux): ")
            search_shodan(f"os:{os_name}", file_name)
        elif choice == 6:
            location = input("Enter country code (e.g., US, CA): ")
            search_shodan(f"port:554 country:{location} has_screenshot:true", file_name)
        elif choice == 7:
            header = input("Enter HTTP header (e.g., server, x-powered-by): ")
            search_shodan(f"http.header:{header}", file_name)
        elif choice == 8:
            protocol = input("Enter protocol/product name (e.g., SSH, FTP): ")
            search_shodan(f"product:{protocol}", file_name)
        elif choice == 9:
            search_shodan("has_default_password:true", file_name)
        elif choice == 10:
            search_shodan("tag:ics", file_name)
        elif choice == 11:
            city = input("Enter city name: ")
            search_shodan(f"city:{city}", file_name)
        elif choice == 12:
            search_shodan("firewall", file_name)
        elif choice == 13:
            search_shodan("port:23", file_name)
        elif choice == 14:
            break

# Main Menu
def main_menu():
    display_banner()
    file_name = input("Enter the output file name (e.g., results.txt): ")

    while True:
        print("\n--- Shodan Quest Main Menu ---")
        print("1. Predefined Queries\n2. Custom Search\n3. Search by CVE\n4. Exit")

        choice = int(input("Choose an option: "))
        if choice == 1:
            print("\n--- Predefined Queries ---")
            for i, (name, query) in enumerate(search_queries.items(), 1):
                print(f"{i}. {name}")
            predefined_choice = int(input("Choose a predefined query: "))
            query = list(search_queries.values())[predefined_choice - 1]
            search_shodan(query, file_name)
        elif choice == 2:
            custom_search_menu(file_name)
        elif choice == 3:
            print("\n--- Vulnerability CVE Queries ---")
            for i, vuln_query in enumerate(vuln_queries, 1):
                print(f"{i}. {vuln_query}")
            vuln_choice = int(input("Choose a CVE query: "))
            search_shodan(vuln_queries[vuln_choice - 1], file_name)
        elif choice == 4:
            print("Exiting program.")
            break

# Run the main menu
main_menu()
