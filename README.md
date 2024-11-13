# Shodan-Quest

Shodan-Quest is an advanced Python-based tool for performing comprehensive searches on the [Shodan](https://www.shodan.io/) database. It offers predefined search queries for various devices, services, and vulnerabilities, as well as a custom search feature. This tool is designed for cybersecurity researchers and penetration testers looking to identify exposed services, vulnerable devices, and misconfigurations on the internet.

## Features

- **API Key Management**: Automatically save and validate your Shodan API key.
- **Predefined Search Queries**: Includes 50+ ready-to-use queries for finding exposed services like cameras, databases, and IoT devices.
- **Vulnerability Searches**: Quickly identify services affected by specific CVEs.
- **Custom Search Menu**: Allows users to perform tailored Shodan searches based on various criteria.
- **Export Results**: Saves search results to a file for later analysis.

## Predefined Search Queries

The tool includes several predefined search categories:

- **IoT Devices**: Cameras, SCADA, Industrial Control Systems
- **Databases**: MongoDB, MySQL, ElasticSearch, Redis
- **Networking Services**: FTP, Telnet, OpenSSH, Remote Desktop (RDP)
- **Vulnerabilities**: CVE-based searches for popular exploits
- **Web Services**: Apache, Nginx, OpenVPN
- **Industrial Devices**: PLCs, HMI Systems, HVAC, Energy Management Systems

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/shodan-quest.git
   cd shodan-quest

    Install required Python packages:

    pip install -r requirements.txt

        Ensure you have Python 3.8+ installed.

    Set up Shodan API Key:
        The script will prompt you to enter your API key on the first run.
        Your API key will be saved in shodan_key.txt for future use.

## Usage

Run the script using:

```python quest.py ```

Main Menu Options

    1. Search by Predefined Queries: Choose from a list of predefined searches, including IoT devices, databases, and web services.
    2. Search by Vulnerabilities: Perform searches for specific CVEs.
    3. Custom Search Menu: Create tailored Shodan searches based on criteria like IP, port, country, and protocol.
    4. Exit: Exit the program.

Custom Search Examples

    Search for IP address:
        Input: Enter IP address: 192.168.1.1
    Search for specific port:
        Input: Enter service port (e.g., 80, 443): 22
    Search for a vulnerability by CVE ID:
        Input: Enter vulnerability keyword (e.g., CVE ID): CVE-2021-26855

Example Output

```The search results are saved to a file in the format:

Results found: 100
Results saved to output.txt
```

## Requirements

    Python 3.8+
    Shodan Python library: Install via pip install shodan
    PrettyPrint (pprint): Part of the Python Standard Library
    Internet Access: For API requests to Shodan

## Contributing

Contributions are welcome! If you have any ideas or features to add, please open an issue or submit a pull request.

  Steps to Contribute

    Fork the repository.
    Create a new branch (git checkout -b feature/YourFeature).
    Commit your changes (git commit -am 'Add new feature').
    Push to the branch (git push origin feature/YourFeature).
    Open a Pull Request.

## File Structure

```
Shodan-Quest/
├── shodan_quest.py      # Main script file
├── shodan_key.txt       # Saved Shodan API key (auto-generated)
└── results.txt          # Output file for search results (user-defined)
```

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is intended for educational purposes and ethical cybersecurity research only. Unauthorized scanning or probing of systems without permission is illegal and unethical. Use responsibly.
Contact

For issues, questions, or suggestions, feel free to open an issue on GitHub.
