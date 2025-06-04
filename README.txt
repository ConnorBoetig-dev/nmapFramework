# Network Mapping Framework

A comprehensive Python-based framework for automated network discovery, scanning, analysis, and reporting using Nmap. Designed for IT teams to gain actionable insights from network scans.

## 🚀 Quick Start

### 1. Setup
```bash
# Run the setup script
chmod +x setup_project.sh
./setup_project.sh

# Activate the virtual environment
cd network_mapper
source venv/bin/activate
```

### 2. Run a Complete Scan
```bash
# Basic network scan with reports
python3 pipeline.py 192.168.1.0/24

# Quick scan for fast results
python3 pipeline.py 192.168.1.0/24 -t quick

# Comprehensive scan with OS detection (requires sudo)
sudo python3 pipeline.py 192.168.1.0/24 -t comprehensive
```

## 📁 Project Structure

```
network_mapper/
├── scripts/
│   ├── scanning/
│   │   └── nmap_scanner.py      # Automated nmap scanning
│   ├── parsing/
│   │   └── xml_parser.py        # XML to JSON parser
│   └── reporting/
│       └── report_generator.py  # HTML/text report generator
├── output/
│   ├── xml/raw/                 # Raw nmap XML files
│   ├── processed/               # Parsed JSON data
│   ├── reports/                 # Generated reports
│   └── logs/                    # Scan logs
├── config/                      # Configuration files
├── templates/                   # Report templates
└── pipeline.py                  # Main pipeline orchestrator
```

## 🛠️ Components

### 1. Scanner (`nmap_scanner.py`)
- **Purpose**: Automated nmap scanning with various scan types
- **Features**:
  - Multiple scan profiles (quick, comprehensive, full TCP, UDP top ports)
  - Configurable timing templates
  - Automatic XML output generation
  - Scan summary tracking

**Usage**:
```bash
# Direct scanner usage
python3 scripts/scanning/nmap_scanner.py 192.168.1.0/24 -t comprehensive -T 4
```

**Scan Types**:
- `quick`: Fast scan of top 100 ports
- `comprehensive`: Full service detection + OS detection
- `full_tcp`: All TCP ports with service detection
- `udp_top`: Top 1000 UDP ports
- `discovery`: Host discovery only

### 2. Parser (`xml_parser.py`)
- **Purpose**: Convert nmap XML output to structured JSON data
- **Features**:
  - Extracts hosts, ports, services, OS information
  - Identifies potential security issues
  - Generates actionable insights
  - Exports to JSON and CSV formats

**Usage**:
```bash
python3 scripts/parsing/xml_parser.py output/xml/raw/scan_file.xml -o output/processed
```

**Insights Generated**:
- Host inventory and status
- Service distribution and versions
- Operating system detection
- Open port analysis
- Security concern identification

### 3. Report Generator (`report_generator.py`)
- **Purpose**: Create professional HTML and text reports
- **Features**:
  - Executive summary with key metrics
  - Security issues prioritization
  - Visual host and service breakdown
  - Actionable recommendations

**Usage**:
```bash
python3 scripts/reporting/report_generator.py output/processed/data.json -o output/reports
```

### 4. Pipeline Runner (`pipeline.py`)
- **Purpose**: Orchestrate the complete workflow
- **Features**:
  - End-to-end automation
  - Progress tracking
  - Error handling and recovery
  - Quick result summaries

## 📊 Report Features

### HTML Reports Include:
- **Executive Dashboard**: Key metrics at a glance
- **Security Analysis**: Prioritized security concerns with severity levels
- **Network Statistics**: Service distribution, common ports, OS breakdown
- **Host Details**: Per-host analysis with open ports and services
- **Visual Design**: Professional, responsive layout

### Text Reports Include:
- **Summary Statistics**: Host counts, port counts, service counts
- **Security Issues**: Prioritized list of concerns
- **Service Distribution**: Most common services found
- **Host Inventory**: Detailed per-host breakdown

## 🔍 Scan Examples

### Home/Small Office Network
```bash
# Quick inventory scan
python3 pipeline.py 192.168.1.0/24 -t quick

# Comprehensive analysis
sudo python3 pipeline.py 192.168.1.0/24 -t comprehensive
```

### Corporate Network Segment
```bash
# Large network discovery
python3 pipeline.py 10.0.0.0/16 -t discovery

# Service detection on specific range
python3 pipeline.py 10.0.1.0/24 -t comprehensive -T 4
```

### Server Subnet Analysis
```bash
# Full TCP port scan
sudo python3 pipeline.py 172.16.10.0/24 -t full_tcp

# UDP service detection
sudo python3 pipeline.py 172.16.10.0/24 -t udp_top
```

## 🛡️ Security Insights

The framework automatically identifies:

### High-Priority Issues:
- Unencrypted protocols (Telnet, FTP, HTTP)
- Database services exposed to network
- Windows file sharing (SMB/NetBIOS)
- Remote access services (RDP, SSH)

### Analysis Features:
- **Service Version Detection**: Identifies outdated software
- **Protocol Analysis**: Flags insecure communication methods
- **Port Risk Assessment**: Highlights commonly exploited ports
- **OS Fingerprinting**: Maps operating system distribution

## ⚙️ Configuration

### Timing Templates:
- **T0**: Paranoid (very slow, IDS evasion)
- **T1**: Sneaky (slow, IDS evasion)
- **T2**: Polite (slower, less bandwidth intensive)
- **T3**: Normal (default)
- **T4**: Aggressive (faster, assumes fast network)
- **T5**: Insane (very fast, may miss results)

### Recommended Settings:
- **Internal Networks**: T4 or T3
- **External/Sensitive**: T2 or T1
- **Quick Checks**: T4 with quick scan type

## 📋 Output Files

### Generated Files:
1. **Raw XML**: `output/xml/raw/scan_comprehensive_TIMESTAMP.xml`
2. **Parsed JSON**: `output/processed/scan_comprehensive_TIMESTAMP_parsed.json`
3. **HTML Report**: `output/reports/scan_comprehensive_report_TIMESTAMP.html`
4. **Text Summary**: `output/reports/scan_comprehensive_report_TIMESTAMP.txt`
5. **CSV Data**: `output/processed/scan_comprehensive_TIMESTAMP_csv/`

## 🔧 Advanced Usage

### Individual Component Usage:

#### Scan Only:
```bash
python3 pipeline.py 192.168.1.0/24 --scan-only
```

#### Parse Existing XML:
```bash
python3 scripts/parsing/xml_parser.py existing_scan.xml
```

#### Generate Report from JSON:
```bash
python3 scripts/reporting/report_generator.py parsed_data.json --format html
```

### Custom Workflows:
```bash
# Multiple scan types
python3 scripts/scanning/nmap_scanner.py 192.168.1.0/24 -t comprehensive
python3 scripts/scanning/nmap_scanner.py 192.168.1.0/24 -t udp_top

# Batch processing
for scan in output/xml/raw/*.xml; do
    python3 scripts/parsing/xml_parser.py "$scan"
done
```

## 🚨 Best Practices

### Security Considerations:
1. **Authorization**: Only scan networks you own or have permission to test
2. **Timing**: Use appropriate timing templates to avoid network disruption
3. **Scope**: Define clear scan boundaries
4. **Documentation**: Keep scan logs for compliance

### Performance Tips:
1. **Network Segmentation**: Scan smaller subnets for faster results
2. **Parallel Scanning**: Run multiple targeted scans simultaneously
3. **Resource Management**: Monitor system resources during large scans
4. **Scheduling**: Run comprehensive scans during off-hours

## 🐛 Troubleshooting

### Common Issues:

#### Permission Errors:
```bash
# Solution: Run with sudo for advanced features
sudo python3 pipeline.py target -t comprehensive
```

#### Slow Scans:
```bash
# Solution: Increase timing or reduce scope
python3 pipeline.py target -T 4 -t quick
```

#### Missing Dependencies:
```bash
# Solution: Reinstall requirements
pip install -r requirements.txt
```

### Debug Mode:
```bash
# Enable verbose output
python3 pipeline.py target --verbose
```

## 📈 Integration Ideas

### Scheduled Scanning:
```bash
# Add to crontab for daily scans
0 2 * * * cd /path/to/network_mapper && python3 pipeline.py 192.168.1.0/24 -t quick
```

### CI/CD Integration:
- Use for infrastructure change detection
- Automate security compliance checks
- Monitor service inventory changes

### Database Storage:
- Extend parser to store results in databases
- Create historical trending analysis
- Build alerting for new services/hosts

## 🤝 Contributing

Feel free to extend the framework with:
- Additional scan types
- Custom report formats
- Database integrations
- Alert mechanisms
- API endpoints

## 📄 License

This framework is designed for legitimate network administration and security testing. Ensure you have proper authorization before scanning any networks.
