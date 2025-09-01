#requires -RunAsAdministrator

<#
.SYNOPSIS
    Runs an Nmap scan on a specified network, saves the results as XML,
    and then uses a Python script to parse the XML into an HTML report.

.DESCRIPTION
    This script is a PowerShell equivalent of the original 'run_scan.sh' script.
    It automates the process of network scanning and reporting for a Windows environment.

    It requires Nmap and Python 3 to be installed and available in the system's PATH.
    The script must be run with Administrator privileges for Nmap's OS detection (-O) to work.
#>

# --- Configuration ---

# Set the network range you want to scan.
# Examples: "192.168.1.0/24", "10.0.0.1-254"
$NETWORK_CIDR = "192.168.1.0/24"

# Set the ABSOLUTE path where you want to store the scripts and results.
# IMPORTANT: This script assumes parse_nmap.py is in this same directory.
# Example for a standard web server on Windows (IIS):
$OUTPUT_DIR = "C:\inetpub\wwwroot\nmap-dashboard"

# --- Script Logic ---

# Function to write a timestamped log message to the console
function Write-Log {
    param([string]$Message)
    Write-Host "($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')): $Message"
}

Write-Log "Starting network scan for $NETWORK_CIDR..."

# Ensure the output directory exists. The -Force parameter creates parent directories if needed.
try {
    New-Item -ItemType Directory -Path $OUTPUT_DIR -Force -ErrorAction Stop | Out-Null
}
catch {
    Write-Log "FATAL: Could not create output directory at '$OUTPUT_DIR'. Please check permissions."
    exit 1
}

# Define file paths using a robust method
$XML_OUTPUT = Join-Path -Path $OUTPUT_DIR -ChildPath "scan_results.xml"
$HTML_OUTPUT = Join-Path -Path $OUTPUT_DIR -ChildPath "index.html"
$PYTHON_PARSER = Join-Path -Path $OUTPUT_DIR -ChildPath "parse_nmap.py"

# Check for prerequisites
if (-not (Test-Path -Path $PYTHON_PARSER -PathType Leaf)) {
    Write-Log "FATAL: Python parser script not found at '$PYTHON_PARSER'"
    exit 1
}

if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Log "FATAL: nmap.exe not found. Please ensure Nmap is installed and in your system's PATH."
    exit 1
}

$python_executable = if (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" } else { "python" }
if ($python_executable -eq "python") {
    Write-Log "WARNING: 'python3' command not found. Using 'python'. Ensure this is Python 3."
}


# Run the Nmap scan.
# -sV: Probe open ports to determine service/version info
# -O: Enable OS detection (requires Administrator privileges)
# -oX: Output scan in XML format
# --host-timeout: Spend no more than this much time on a single host
# -T4: Aggressive timing template (faster scans)
Write-Log "Running Nmap... This may take a while."
$nmapArgs = @(
    "-sV",
    "-O",
    "--host-timeout", "20m",
    "-T4",
    $NETWORK_CIDR,
    "-oX",
    $XML_OUTPUT
)

& nmap @nmapArgs

if ($LASTEXITCODE -ne 0) {
    Write-Log "WARNING: Nmap exited with a non-zero status code: $LASTEXITCODE. The scan may have failed or been incomplete."
}

# Check if the XML file was created. If not, Nmap failed.
if (-not (Test-Path -Path $XML_OUTPUT -PathType Leaf)) {
    Write-Log "Nmap scan failed. XML output not found at '$XML_OUTPUT'."
    # We can still run the parser to generate an error page, as in the original script.
    # Note: This assumes the Python script can handle a non-existent input file.
    & $python_executable $PYTHON_PARSER $XML_OUTPUT -o $HTML_OUTPUT
    exit 1
}

Write-Log "Scan complete. Generating HTML report..."

# Run the Python script to process the XML and generate the HTML page.
try {
    & $python_executable $PYTHON_PARSER $XML_OUTPUT -o $HTML_OUTPUT
    if ($LASTEXITCODE -ne 0) {
        throw "Python script exited with code $LASTEXITCODE"
    }
}
catch {
    Write-Log "FATAL: An error occurred while running the Python parser."
    Write-Error $_
    exit 1
}

Write-Log "Report generated successfully at '$HTML_OUTPUT'"
Write-Host "-----------------------------------------------------"

Write-Host "Scan and report complete. You can view the results in your web browser."
Write-Host "If you are running a local web server, navigate to:"