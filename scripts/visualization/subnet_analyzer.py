#!/usr/bin/env python3
"""
Subnet Analyzer
Analyzes network segments and VLAN hints from scan data
"""

import ipaddress
from collections import defaultdict, Counter
from typing import Dict, List, Any


class SubnetAnalyzer:
    def __init__(self):
        self.subnets = defaultdict(list)
        self.vlan_hints = {}
        
    def analyze_network_segments(self, scan_data: Dict) -> Dict:
        """Analyze network segments and potential VLANs"""
        hosts = scan_data.get("hosts", [])
        
        # Group hosts by subnet
        subnet_info = defaultdict(lambda: {
            "hosts": [],
            "services": Counter(),
            "device_types": Counter(),
            "common_ports": Counter()
        })
        
        for host in hosts:
            ip = host["addresses"].get("ipv4")
            if not ip:
                continue
                
            # Try different subnet sizes
            for prefix in [24, 16, 8]:
                try:
                    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    subnet_key = str(network)
                    
                    subnet_info[subnet_key]["hosts"].append(ip)
                    
                    # Analyze device type
                    if "device_classification" in host:
                        device_type = host["device_classification"].get("device_type", "unknown")
                        subnet_info[subnet_key]["device_types"][device_type] += 1
                    
                    # Analyze services
                    for port in host.get("ports", []):
                        if port["state"] == "open":
                            service = port["service"].get("name", "unknown")
                            subnet_info[subnet_key]["services"][service] += 1
                            subnet_info[subnet_key]["common_ports"][port["port"]] += 1
                            
                except Exception:
                    continue
        
        # Analyze for VLAN patterns
        vlan_hints = self._detect_vlan_patterns(subnet_info)
        
        # Prepare analysis results
        analysis = {
            "segments": {},
            "vlan_hints": vlan_hints,
            "summary": {
                "total_segments": len(subnet_info),
                "largest_segment": "",
                "most_common_service": "",
                "segregation_score": 0
            }
        }
        
        # Process each segment
        for subnet, info in subnet_info.items():
            if len(info["hosts"]) > 0:  # Only include non-empty subnets
                analysis["segments"][subnet] = {
                    "host_count": len(info["hosts"]),
                    "primary_device_type": info["device_types"].most_common(1)[0][0] if info["device_types"] else "unknown",
                    "top_services": [s[0] for s in info["services"].most_common(3)],
                    "common_ports": [p[0] for p in info["common_ports"].most_common(5)]
                }
        
        # Calculate summary statistics
        if analysis["segments"]:
            largest = max(analysis["segments"].items(), key=lambda x: x[1]["host_count"])
            analysis["summary"]["largest_segment"] = largest[0]
            
            all_services = Counter()
            for info in subnet_info.values():
                all_services.update(info["services"])
            if all_services:
                analysis["summary"]["most_common_service"] = all_services.most_common(1)[0][0]
        
        # Calculate segregation score (0-100)
        # Higher score = better network segregation
        if len(analysis["segments"]) > 1:
            avg_hosts_per_segment = sum(s["host_count"] for s in analysis["segments"].values()) / len(analysis["segments"])
            if avg_hosts_per_segment < 50:
                analysis["summary"]["segregation_score"] = min(100, len(analysis["segments"]) * 10)
            else:
                analysis["summary"]["segregation_score"] = max(0, 100 - int(avg_hosts_per_segment))
        
        return analysis
    
    def _detect_vlan_patterns(self, subnet_info: Dict) -> Dict:
        """Detect potential VLAN patterns based on subnet characteristics"""
        vlan_hints = {
            "potential_vlans": [],
            "recommendations": []
        }
        
        for subnet, info in subnet_info.items():
            if len(info["hosts"]) < 2:
                continue
                
            # Check for common VLAN patterns
            device_types = info["device_types"]
            services = info["services"]
            
            # Pattern 1: Printer VLAN
            if device_types.get("printer", 0) > device_types.get("workstation", 0):
                vlan_hints["potential_vlans"].append({
                    "vlan_id": f"Printer_VLAN_{subnet}",
                    "type": "printer_vlan",
                    "confidence": 0.8,
                    "subnets": [subnet]
                })
            
            # Pattern 2: Server VLAN
            if device_types.get("server", 0) >= 2 or services.get("http", 0) + services.get("https", 0) >= 3:
                vlan_hints["potential_vlans"].append({
                    "vlan_id": f"Server_VLAN_{subnet}",
                    "type": "server_vlan",
                    "confidence": 0.7,
                    "subnets": [subnet]
                })
            
            # Pattern 3: IoT/Management VLAN
            if device_types.get("iot", 0) >= 2 or device_types.get("router", 0) + device_types.get("switch", 0) >= 2:
                vlan_hints["potential_vlans"].append({
                    "vlan_id": f"Management_VLAN_{subnet}",
                    "type": "management_vlan",
                    "confidence": 0.6,
                    "subnets": [subnet]
                })
            
            # Pattern 4: Guest/DMZ VLAN (isolated segments with few hosts)
            if len(info["hosts"]) < 10 and services.get("http", 0) > 0:
                vlan_hints["potential_vlans"].append({
                    "vlan_id": f"DMZ_VLAN_{subnet}",
                    "type": "dmz_vlan",
                    "confidence": 0.5,
                    "subnets": [subnet]
                })
        
        # Add recommendations based on findings
        if not vlan_hints["potential_vlans"]:
            vlan_hints["recommendations"].append("Consider implementing VLANs for better network segmentation")
        else:
            vlan_hints["recommendations"].append(f"Detected {len(vlan_hints['potential_vlans'])} potential VLAN segments")
            vlan_hints["recommendations"].append("Verify VLAN configuration with network documentation")
        
        return vlan_hints
