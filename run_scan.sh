#!/bin/bash

# --- Configuration ---
# Set the network range you want to scan.
# Examples: 192.168.1.0/24, 10.0.0.1-254
NETWORK_CIDR="192.168.1.0/24"

# Set the ABSOLUTE path where you want to store the scripts and results.
# IMPORTANT: This script assumes parse_nmap.py is in this same directory.
# Example for a standard web server on Linux:
OUTPUT_DIR="/var/www/html/nmap-dashboard"

# --- Script Logic ---
echo "$(date): Starting network scan for ${NETWORK_CIDR}..."

# Ensure the output directory exists
mkdir -p "${OUTPUT_DIR}"

# Define file paths
XML_OUTPUT="${OUTPUT_DIR}/scan_results.xml"
HTML_OUTPUT="${OUTPUT_DIR}/index.html"
PYTHON_PARSER="${OUTPUT_DIR}/parse_nmap.py"

# Check if the python script exists
if [ ! -f "${PYTHON_PARSER}" ]; then
    echo "Error: Python parser script not found at ${PYTHON_PARSER}"
    exit 1
fi

# Run the Nmap scan.
# -sV: Probe open ports to determine service/version info
# -O: Enable OS detection (requires root/sudo)
# -oX: Output scan in XML format
# --host-timeout: Spend no more than this much time on a single host
# -T4: Aggressive timing template (faster scans)
# Using 'sudo' is crucial for OS detection (-O) and some other scan types.
sudo nmap -sV -O --host-timeout 20m -T4 ${NETWORK_CIDR} -oX "${XML_OUTPUT}"

# Check if the XML file was created. If not, Nmap failed.
if [ ! -f "${XML_OUTPUT}" ]; then
    echo "$(date): Nmap scan failed. XML output not found."
    # We can still run the parser to generate an error page.
    python3 "${PYTHON_PARSER}" "${XML_OUTPUT}" "${HTML_OUTPUT}"
    exit 1
fi

echo "$(date): Scan complete. Generating HTML report..."

# Run the Python script to process the XML and generate the HTML page.
python3 "${PYTHON_PARSER}" "${XML_OUTPUT}" "-o ${HTML_OUTPUT}"

echo "$(date): Report generated successfully at ${HTML_OUTPUT}"
echo "-----------------------------------------------------"
