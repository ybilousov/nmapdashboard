import sys
import argparse
from lxml import etree

def parse_nmap_xml(xml_file):
    """
    Parses an Nmap XML file, recovering from malformed XML if possible.

    Args:
        xml_file (str): Path to the Nmap XML file.

    Returns:
        tuple: A tuple containing (list of hosts, nmap command string).
               Returns ([], None) if parsing fails.
    """
    hosts_data = []
    nmap_command = "N/A"
    try:
        # Use a recovering parser to handle malformed XML, as requested.
        # This will try its best to parse even broken XML documents.
        parser = etree.XMLParser(recover=True, encoding='utf-8')
        tree = etree.parse(xml_file, parser)
        root = tree.getroot()

        # Check for nmaprun element
        if root.tag != 'nmaprun':
            print(f"Error: The provided file '{xml_file}' does not appear to be a valid Nmap XML output.", file=sys.stderr)
            return [], None

        # Extract the original nmap command
        nmap_command = root.get('args', 'N/A')

        for host in root.findall('host'):
            host_info = {
                'ip': '',
                'hostname': '',
                'status': '',
                'ports': []
            }

            # --- Get Host Status ---
            status_element = host.find('status')
            if status_element is not None:
                host_info['status'] = status_element.get('state', 'unknown')

            # --- Get IP Address (prefer IPv4) ---
            address_element = host.find("address[@addrtype='ipv4']")
            if address_element is None:
                address_element = host.find("address[@addrtype='ipv6']") # Fallback to IPv6
            if address_element is not None:
                host_info['ip'] = address_element.get('addr')

            # --- Get Hostname ---
            hostname_element = host.find('hostnames/hostname')
            if hostname_element is not None:
                host_info['hostname'] = hostname_element.get('name', '')

            # --- Get Port Information ---
            ports_element = host.find('ports')
            if ports_element is not None:
                for port in ports_element.findall('port'):
                    port_info = {
                        'portid': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': '',
                        'service_name': '',
                        'product': '',
                        'version': ''
                    }
                    state_element = port.find('state')
                    if state_element is not None:
                        port_info['state'] = state_element.get('state')

                    service_element = port.find('service')
                    if service_element is not None:
                        port_info['service_name'] = service_element.get('name', 'unknown')
                        port_info['product'] = service_element.get('product', '')
                        port_info['version'] = service_element.get('version', '')

                    host_info['ports'].append(port_info)
            
            # Only add hosts that have an IP address
            if host_info['ip']:
                hosts_data.append(host_info)

    except etree.XMLSyntaxError as e:
        print(f"Error parsing XML file '{xml_file}': {e}", file=sys.stderr)
        return [], None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return [], None
        
    return hosts_data, nmap_command

def generate_html_report(hosts_data, nmap_command, output_file, input_file):
    """
    Generates an HTML report from the parsed Nmap data.

    Args:
        hosts_data (list): A list of host data dictionaries.
        nmap_command (str): The nmap command that was run.
        output_file (str): Path to the output HTML file.
        input_file (str): Path of the source XML file for the report header.
    """
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }}
        h1 {{ color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 10px; }}
        h2 {{ color: #0275d8; margin-top: 2em; border-bottom: 1px solid #ccc; }}
        .report-meta {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 2em; font-family: "Courier New", Courier, monospace; }}
        .host-block {{ background-color: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 1.5em; margin-bottom: 1.5em; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1em; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #f7f7f7; font-weight: 600; }}
        .status-up {{ color: #5cb85c; font-weight: bold; }}
        .status-down {{ color: #d9534f; font-weight: bold; }}
        .port-open {{ color: #5cb85c; font-weight: bold; }}
        .no-ports {{ font-style: italic; color: #777; }}
        .footer {{ margin-top: 2em; text-align: center; font-size: 0.9em; color: #777; }}
    </style>
</head>
<body>
    <h1>Nmap Scan Report</h1>
    <div class="report-meta">
        <strong>Source File:</strong> {input_file}<br>
        <strong>Scan Command:</strong> <code>{nmap_command}</code>
    </div>
    """

    if not hosts_data:
        html += "<p>No hosts found in the scan results or the XML file was empty/invalid.</p>"
    else:
        for host in sorted(hosts_data, key=lambda h: h.get('ip', '')):
            ip = host.get('ip', 'N/A')
            hostname = f"({host.get('hostname')})" if host.get('hostname') else ''
            status = host.get('status', 'unknown')
            status_class = 'status-up' if status == 'up' else 'status-down'

            html += f"""
    <div class="host-block">
        <h2>Host: {ip} {hostname} - <span class="{status_class}">{status.upper()}</span></h2>
            """

            if host['ports']:
                html += """
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                """
                # Sort ports by port number (as integer)
                for port in sorted(host['ports'], key=lambda p: int(p['portid'])):
                    state_class = 'port-open' if port['state'] == 'open' else ''
                    html += f"""
                <tr>
                    <td>{port['portid']}</td>
                    <td>{port['protocol']}</td>
                    <td class="{state_class}">{port['state']}</td>
                    <td>{port.get('service_name', '')}</td>
                    <td>{port.get('product', '')}</td>
                    <td>{port.get('version', '')}</td>
                </tr>
                    """
                html += "</tbody></table>"
            else:
                html += "<p class='no-ports'>No open ports found on this host (or ports were not scanned).</p>"
            
            html += "</div>"

    html += """
    <div class="footer">
        <p>Report generated by Gemini Code Assist Nmap Parser.</p>
    </div>
</body>
</html>
    """

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"Successfully generated HTML report: {output_file}")
    except IOError as e:
        print(f"Error writing to output file '{output_file}': {e}", file=sys.stderr)

def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(
        description="Parse an Nmap XML file and generate an HTML report.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("input_xml", help="Path to the Nmap XML input file.")
    parser.add_argument(
        "-o", "--output",
        help="Path to the HTML output file. Defaults to input filename with .html extension.",
        default=None
    )
    args = parser.parse_args()

    input_file = args.input_xml
    output_file = args.output
    if output_file is None:
        if input_file.lower().endswith('.xml'):
            output_file = input_file[:-4] + '.html'
        else:
            output_file = input_file + '.html'

    print(f"Parsing Nmap XML file: {input_file}")
    hosts, nmap_command = parse_nmap_xml(input_file)
    
    if hosts:
        print(f"Found {len(hosts)} host(s) in the scan.")
        generate_html_report(hosts, nmap_command, output_file, input_file)
    else:
        print("No host data was parsed. HTML report will not be generated.")
        sys.exit(1)

if __name__ == "__main__":
    main()

