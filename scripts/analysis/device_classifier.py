#!/usr/bin/env python3
"""
Device Classification Engine
Fingerprints network devices based on OS, services, ports, and other indicators
"""

import re
from typing import Dict, List, Tuple, Any
from collections import defaultdict

class DeviceClassifier:
    """
    Advanced device fingerprinting engine that analyzes host data
    to determine device type with confidence scoring
    """
    
    def __init__(self):
        # Define port signatures for different device types
        self.port_signatures = {
            'router': {
                'common_ports': [22, 23, 80, 443, 161],
                'strong_indicators': [179, 1723, 1701, 2601, 2602],  # BGP, PPTP, L2TP, Zebra
                'services': ['cisco', 'juniper', 'mikrotik', 'vyos', 'ubiquiti']
            },
            'switch': {
                'common_ports': [22, 23, 80, 443, 161],
                'strong_indicators': [4786, 8291],  # Cisco Smart Install, MikroTik
                'services': ['cisco', 'hp', 'dell', 'arista']
            },
            'firewall': {
                'common_ports': [22, 443, 8443],
                'strong_indicators': [500, 4500, 1194, 981],  # IPSec, OpenVPN, SonicWall
                'services': ['pfsense', 'fortinet', 'sonicwall', 'paloalto', 'checkpoint']
            },
            'server': {
                'common_ports': [22, 80, 443, 3389, 5900],
                'strong_indicators': [21, 25, 110, 143, 389, 636, 1433, 3306, 5432],
                'services': ['apache', 'nginx', 'iis', 'mysql', 'postgresql', 'ldap']
            },
            'workstation': {
                'common_ports': [135, 139, 445, 3389, 5900],
                'strong_indicators': [5357, 7680],  # WSD, Windows Update Delivery
                'services': ['microsoft-ds', 'netbios-ssn', 'vnc', 'rdp']
            },
            'printer': {
                'common_ports': [80, 443, 631, 9100],
                'strong_indicators': [515, 9101, 9102],  # LPD, JetDirect
                'services': ['cups', 'jetdirect', 'lpd', 'ipp']
            },
            'iot': {
                'common_ports': [80, 443, 8080, 8443],
                'strong_indicators': [1883, 8883, 5683, 1900, 554],  # MQTT, CoAP, UPnP, RTSP
                'services': ['camera', 'sensor', 'thermostat', 'light', 'upnp']
            },
            'storage': {
                'common_ports': [22, 80, 443, 139, 445],
                'strong_indicators': [111, 2049, 3260, 873],  # NFS, iSCSI, rsync
                'services': ['nfs', 'iscsi', 'smb', 'synology', 'qnap', 'netapp']
            }
        }
        
        # OS patterns for device classification
        self.os_patterns = {
            'router': [
                r'cisco.*ios', r'junos', r'vyos', r'mikrotik', r'edgeos',
                r'fortios', r'panos', r'routeros'
            ],
            'switch': [
                r'cisco.*catalyst', r'procurve', r'powerconnect', r'arista'
            ],
            'firewall': [
                r'pfsense', r'fortinet', r'sonicwall', r'checkpoint', r'asa'
            ],
            'server': [
                r'windows.*server', r'linux.*server', r'ubuntu.*server',
                r'centos', r'redhat', r'debian', r'esxi', r'vmware'
            ],
            'workstation': [
                r'windows.*\d+', r'ubuntu.*desktop', r'macos', r'mac os x'
            ],
            'printer': [
                r'jetdirect', r'cups', r'brother', r'canon', r'epson', r'lexmark'
            ],
            'iot': [
                r'embedded', r'busybox', r'uclinux', r'openwrt', r'ddwrt'
            ],
            'storage': [
                r'freenas', r'synology', r'qnap', r'netapp', r'emc', r'truenas'
            ]
        }
        
        # Service banner patterns
        self.banner_patterns = {
            'router': ['cisco', 'juniper', 'mikrotik', 'ubiquiti'],
            'printer': ['hp jetdirect', 'brother', 'canon', 'epson', 'xerox'],
            'storage': ['synology', 'qnap', 'freenas', 'netapp'],
            'iot': ['camera', 'nvr', 'dvr', 'thermostat', 'sensor']
        }
    
    def classify_device(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a device based on comprehensive analysis of host data
        
        Args:
            host_data: Dictionary containing host information from nmap scan
            
        Returns:
            Dictionary with device classification results
        """
        scores = defaultdict(float)
        evidence = defaultdict(list)
        
        # Extract relevant data
        open_ports = self._extract_open_ports(host_data)
        services = self._extract_services(host_data)
        os_info = self._extract_os_info(host_data)
        
        # 1. Port-based analysis
        port_scores, port_evidence = self._analyze_ports(open_ports)
        for device_type, score in port_scores.items():
            scores[device_type] += score
            evidence[device_type].extend(port_evidence[device_type])
        
        # 2. Service-based analysis
        service_scores, service_evidence = self._analyze_services(services)
        for device_type, score in service_scores.items():
            scores[device_type] += score
            evidence[device_type].extend(service_evidence[device_type])
        
        # 3. OS-based analysis
        os_scores, os_evidence = self._analyze_os(os_info)
        for device_type, score in os_scores.items():
            scores[device_type] += score * 2  # OS is a strong indicator
            evidence[device_type].extend(os_evidence[device_type])
        
        # 4. Banner analysis
        banner_scores, banner_evidence = self._analyze_banners(services)
        for device_type, score in banner_scores.items():
            scores[device_type] += score * 1.5
            evidence[device_type].extend(banner_evidence[device_type])
        
        # 5. Apply heuristics and special rules
        scores, evidence = self._apply_heuristics(scores, evidence, host_data)
        
        # Determine best match
        if not scores:
            return {
                'device_type': 'unknown',
                'confidence': 0.0,
                'evidence': ['No identifying features found'],
                'all_scores': {}
            }
        
        # Normalize scores
        max_score = max(scores.values())
        if max_score > 0:
            normalized_scores = {k: v/max_score for k, v in scores.items()}
        else:
            normalized_scores = scores
        
        # Get best match
        best_type = max(normalized_scores.items(), key=lambda x: x[1])
        
        return {
            'device_type': best_type[0],
            'confidence': round(best_type[1], 2),
            'evidence': evidence[best_type[0]],
            'all_scores': dict(normalized_scores)
        }
    
    def _extract_open_ports(self, host_data: Dict) -> List[int]:
        """Extract list of open ports from host data"""
        open_ports = []
        for port in host_data.get('ports', []):
            if port.get('state') == 'open':
                open_ports.append(port.get('port', 0))
        return open_ports
    
    def _extract_services(self, host_data: Dict) -> List[Dict]:
        """Extract service information from host data"""
        services = []
        for port in host_data.get('ports', []):
            if port.get('state') == 'open':
                service_info = port.get('service', {})
                services.append({
                    'port': port.get('port'),
                    'name': service_info.get('name', ''),
                    'product': service_info.get('product', ''),
                    'version': service_info.get('version', ''),
                    'extrainfo': service_info.get('extrainfo', '')
                })
        return services
    
    def _extract_os_info(self, host_data: Dict) -> str:
        """Extract OS information from host data"""
        os_data = host_data.get('os', {})
        if os_data.get('matches'):
            best_match = max(os_data['matches'], key=lambda x: x.get('accuracy', 0))
            return best_match.get('name', '').lower()
        return ''
    
    def _analyze_ports(self, open_ports: List[int]) -> Tuple[Dict, Dict]:
        """Analyze open ports to determine device type"""
        scores = defaultdict(float)
        evidence = defaultdict(list)
        
        for device_type, signature in self.port_signatures.items():
            # Check common ports
            common_matches = sum(1 for port in open_ports if port in signature['common_ports'])
            if common_matches > 0:
                scores[device_type] += common_matches * 0.5
                evidence[device_type].append(f"Has {common_matches} common {device_type} ports")
            
            # Check strong indicator ports
            strong_matches = [port for port in open_ports if port in signature['strong_indicators']]
            if strong_matches:
                scores[device_type] += len(strong_matches) * 2
                evidence[device_type].append(f"Strong indicator ports: {strong_matches}")
        
        return scores, evidence
    
    def _analyze_services(self, services: List[Dict]) -> Tuple[Dict, Dict]:
        """Analyze services to determine device type"""
        scores = defaultdict(float)
        evidence = defaultdict(list)
        
        for service in services:
            service_name = service['name'].lower()
            product = service['product'].lower()
            
            for device_type, signature in self.port_signatures.items():
                for indicator in signature['services']:
                    if indicator in service_name or indicator in product:
                        scores[device_type] += 1.5
                        evidence[device_type].append(
                            f"Service match: {service_name} on port {service['port']}"
                        )
        
        return scores, evidence
    
    def _analyze_os(self, os_string: str) -> Tuple[Dict, Dict]:
        """Analyze OS information to determine device type"""
        scores = defaultdict(float)
        evidence = defaultdict(list)
        
        if not os_string:
            return scores, evidence
        
        for device_type, patterns in self.os_patterns.items():
            for pattern in patterns:
                if re.search(pattern, os_string, re.IGNORECASE):
                    scores[device_type] += 3
                    evidence[device_type].append(f"OS match: {os_string}")
                    break
        
        return scores, evidence
    
    def _analyze_banners(self, services: List[Dict]) -> Tuple[Dict, Dict]:
        """Analyze service banners for device indicators"""
        scores = defaultdict(float)
        evidence = defaultdict(list)
        
        for service in services:
            combined_info = f"{service['product']} {service['extrainfo']}".lower()
            
            for device_type, patterns in self.banner_patterns.items():
                for pattern in patterns:
                    if pattern in combined_info:
                        scores[device_type] += 2
                        evidence[device_type].append(
                            f"Banner match: '{pattern}' in {service['product']}"
                        )
        
        return scores, evidence
    
    def _apply_heuristics(self, scores: Dict, evidence: Dict, host_data: Dict) -> Tuple[Dict, Dict]:
        """Apply special heuristics and rules"""
        open_ports = self._extract_open_ports(host_data)
        
        # Printer heuristic: if only printer ports are open
        printer_ports = {80, 443, 631, 515, 9100, 9101, 9102}
        if open_ports and all(p in printer_ports for p in open_ports):
            scores['printer'] += 3
            evidence['printer'].append("Only printer-related ports are open")
        
        # Server heuristic: many services
        if len(open_ports) > 10:
            scores['server'] += 1
            evidence['server'].append(f"Many services ({len(open_ports)} ports)")
        
        # IoT heuristic: limited services, embedded OS
        if len(open_ports) <= 3 and any(p in [80, 443, 8080] for p in open_ports):
            os_info = self._extract_os_info(host_data)
            if 'embedded' in os_info or 'busybox' in os_info:
                scores['iot'] += 2
                evidence['iot'].append("Limited services with embedded OS")
        
        # Workstation heuristic: Windows networking ports
        windows_ports = {135, 139, 445}
        if windows_ports.issubset(set(open_ports)):
            scores['workstation'] += 2
            evidence['workstation'].append("Windows networking ports detected")
        
        return scores, evidence
    
    def _detect_router(self, host_data: Dict) -> bool:
        """Specialized router detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'router' and result['confidence'] > 0.7
    
    def _detect_switch(self, host_data: Dict) -> bool:
        """Specialized switch detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'switch' and result['confidence'] > 0.7
    
    def _detect_firewall(self, host_data: Dict) -> bool:
        """Specialized firewall detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'firewall' and result['confidence'] > 0.7
    
    def _detect_server(self, host_data: Dict) -> bool:
        """Specialized server detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'server' and result['confidence'] > 0.7
    
    def _detect_workstation(self, host_data: Dict) -> bool:
        """Specialized workstation detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'workstation' and result['confidence'] > 0.7
    
    def _detect_printer(self, host_data: Dict) -> bool:
        """Specialized printer detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'printer' and result['confidence'] > 0.7
    
    def _detect_iot(self, host_data: Dict) -> bool:
        """Specialized IoT device detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'iot' and result['confidence'] > 0.7
    
    def _detect_storage(self, host_data: Dict) -> bool:
        """Specialized storage device detection logic"""
        result = self.classify_device(host_data)
        return result['device_type'] == 'storage' and result['confidence'] > 0.7

def main():
    """Test the device classifier"""
    # Example host data
    test_host = {
        'addresses': {'ipv4': '192.168.1.1'},
        'os': {
            'matches': [
                {'name': 'Cisco IOS 15.2', 'accuracy': 95}
            ]
        },
        'ports': [
            {
                'port': 22,
                'state': 'open',
                'service': {
                    'name': 'ssh',
                    'product': 'Cisco SSH',
                    'version': '2.0'
                }
            },
            {
                'port': 80,
                'state': 'open',
                'service': {
                    'name': 'http',
                    'product': 'Cisco IOS http config'
                }
            },
            {
                'port': 179,
                'state': 'open',
                'service': {
                    'name': 'bgp'
                }
            }
        ]
    }
    
    classifier = DeviceClassifier()
    result = classifier.classify_device(test_host)
    
    print(f"Device Type: {result['device_type']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Evidence: {result['evidence']}")
    print(f"All Scores: {result['all_scores']}")

if __name__ == "__main__":
    main()
