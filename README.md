🌐 Advanced ARP Network Scanner
An advanced ARP Network Scanner built in Python, designed to perform efficient network scans, detect devices on the network, identify duplicate IP and MAC addresses, and summarize results by device manufacturer.

✨ Features
ARP Scanning: Scans specified IP addresses or ranges and retrieves the MAC address and device brand (when available).
Continuous Scanning: Option to run continuous scans at specified intervals.
Duplicate Detection: Detects duplicate IP and MAC addresses in the scan results.
Network Summary: Displays a summary of the scanned devices grouped by manufacturer.
Save Results: Option to save the scan results to a file for later analysis.
Banner Display: A decorative banner at the start of each scan.
Cross-platform Compatibility: Designed for cross-platform compatibility, although some network configurations may vary.
⚙️ Prerequisites
To use this ARP scanner, you need to have Python installed and the following libraries:

scapy
termcolor
manuf
tabulate
Install these dependencies by running:


pip install -r requirements.txt
🚀 Installation
Clone the repository:


git clone https://github.com/hikari1120/reaper.git
cd reaper
Install required libraries:


pip install -r requirements.txt
🔧 Usage
Run the scanner with a target IP or IP range using the following command:


python reaper.py -t <target-ip-or-range> [-i <interface>] [-s <filename>] [-c <interval>]
📝 Options
-t, --target: (Required) Target IP or IP range to scan.
-i, --interface: Specify a network interface to use.
-s, --save: Save scan results to a specified file.
-c, --continuous: Run continuous scan at specified intervals (in seconds).
💻 Example Commands
Basic Scan:


python reaper.py -t 192.168.1.1/24
Continuous Scan (with a 10-second interval):


python reaper.py -t 192.168.1.1/24 -c 10
Save Scan Results:


python reaper.py -t 192.168.1.1/24 -s scan_results.txt
📊 Output
The scanner displays results in a formatted table showing the IP, MAC Address, and Manufacturer (when available).
Duplicates, if any, are highlighted, and a summary by manufacturer is shown.

📝 License
This project is licensed under the MIT License. See the LICENSE file for details.

🤝 Contributions
Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request.
