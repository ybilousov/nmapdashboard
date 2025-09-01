import xml.etree.ElementTree as ET
import csv

def nmap_xml_to_csv(xml_file, csv_file):
    """
    Converts Nmap XML scan results to a CSV file.

    Args:
        xml_file (str): Path to the Nmap XML input file.
        csv_file (str): Path to the CSV output file.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Define CSV headers
    headers = [
        'Host', 'IP Address', 'Port', 'Protocol', 'State', 'Service',
        'Product', 'Version', 'Extra Info', 'Reason', 'Reason TTL',
        'OS Name', 'OS Family', 'OS Gen', 'OS Type', 'OS Accuracy',
        'Hostname Type', 'Hostname Name'
    ]

    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for host in root.findall('host'):
            ip_address = ''
            hostname_type = ''
            hostname_name = ''

            for address in host.findall('address'):
                if address.get('addrtype') == 'ipv4':
                    ip_address = address.get('addr')
            
            for hostname_elem in host.findall('hostnames/hostname'):
                hostname_type = hostname_elem.get('type', '')
                hostname_name = hostname_elem.get('name', '')

            os_name = ''
            os_family = ''
            os_gen = ''
            os_type = ''
            os_accuracy = ''

            for os_match in host.findall('os/osmatch'):
                os_name = os_match.get('name', '')
                os_family = os_match.get('osfamily', '')
                os_gen = os_match.get('osgen', '')
                os_type = os_match.get('type', '')
                os_accuracy = os_match.get('accuracy', '')
                break # Take the first OS match

            ports_elem = host.find('ports')
            if ports_elem:
                for port in ports_elem.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else ''
                    reason = state_elem.get('reason') if state_elem is not None else ''
                    reason_ttl = state_elem.get('reason_ttl') if state_elem is not None else ''

                    service_elem = port.find('service')
                    service = service_elem.get('name') if service_elem is not None else ''
                    product = service_elem.get('product') if service_elem is not None else ''
                    version = service_elem.get('version') if service_elem is not None else ''
                    extra_info = service_elem.get('extrainfo') if service_elem is not None else ''

                    writer.writerow([
                        '', # Host (will be filled by IP or hostname)
                        ip_address,
                        port_id,
                        protocol,
                        state,
                        service,
                        product,
                        version,
                        extra_info,
                        reason,
                        reason_ttl,
                        os_name,
                        os_family,
                        os_gen,
                        os_type,
                        os_accuracy,
                        hostname_type,
                        hostname_name
                    ])
            else: # No ports found, still write host info
                writer.writerow([
                    '', # Host
                    ip_address,
                    '', '', '', '', '', '', '', '', '', # Port related info
                    os_name,
                    os_family,
                    os_gen,
                    os_type,
                    os_accuracy,
                    hostname_type,
                    hostname_name
                ])

if __name__ == '__main__':
    # Example usage:
    nmap_xml_to_csv('scan_results.xml', 'output.csv')
    pass