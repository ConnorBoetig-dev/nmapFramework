#!/usr/bin/env python3
"""
Network Topology Mapper
Analyzes and visualizes network topology from scan data
"""

import json
from pathlib import Path
from collections import defaultdict
import ipaddress
import networkx as nx
import plotly.graph_objects as go
import matplotlib.pyplot as plt
from typing import Dict, List, Any


class NetworkTopologyMapper:
    def __init__(self):
        self.graph = nx.Graph()
        self.topology_data = {
            "nodes": [],
            "edges": [],
            "segments": {},
            "stats": {}
        }
    
    def analyze_topology(self, scan_data: Dict) -> Dict:
        """Analyze network topology from scan data"""
        hosts = scan_data.get("hosts", [])
        
        # Group hosts by subnet
        subnets = defaultdict(list)
        for host in hosts:
            ip = host["addresses"].get("ipv4")
            if ip:
                # Determine subnet (simple /24 assumption)
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnets[str(network)].append(host)
        
        # Build graph
        gateway_count = 0
        for subnet, subnet_hosts in subnets.items():
            # Add subnet node
            subnet_id = f"subnet_{subnet}"
            self.graph.add_node(subnet_id, 
                              type="subnet", 
                              label=subnet,
                              size=len(subnet_hosts))
            
            # Add host nodes
            for host in subnet_hosts:
                ip = host["addresses"].get("ipv4", "unknown")
                host_id = f"host_{ip}"
                
                # Determine if it's a gateway
                is_gateway = False
                if "device_classification" in host:
                    device_type = host["device_classification"].get("device_type", "")
                    if device_type in ["router", "firewall", "gateway"]:
                        is_gateway = True
                        gateway_count += 1
                
                self.graph.add_node(host_id,
                                  type="host",
                                  label=ip,
                                  device_type=host.get("device_classification", {}).get("device_type", "unknown"),
                                  is_gateway=is_gateway)
                
                # Connect host to subnet
                self.graph.add_edge(host_id, subnet_id)
        
        # Prepare topology data
        self.topology_data = {
            "nodes": [
                {
                    "id": node,
                    "label": data.get("label", node),
                    "type": data.get("type", "unknown"),
                    "device_type": data.get("device_type", ""),
                    "is_gateway": data.get("is_gateway", False)
                }
                for node, data in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": edge[0], "target": edge[1]}
                for edge in self.graph.edges()
            ],
            "segments": list(subnets.keys()),
            "stats": {
                "total_nodes": len(self.graph.nodes()),
                "total_subnets": len(subnets),
                "gateway_devices": gateway_count,
                "segments": list(subnets.keys())
            }
        }
        
        return self.topology_data
    
    def generate_plotly_visualization(self, output_file: str, title: str = "Network Topology") -> go.Figure:
        """Generate interactive Plotly visualization"""
        # Use spring layout for positioning
        pos = nx.spring_layout(self.graph, k=2, iterations=50)
        
        # Create edge traces
        edge_trace = go.Scatter(
            x=[],
            y=[],
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')
        
        for edge in self.graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += (x0, x1, None)
            edge_trace['y'] += (y0, y1, None)
        
        # Create node traces by type
        node_traces = []
        
        # Subnet nodes
        subnet_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('type') == 'subnet']
        if subnet_nodes:
            subnet_trace = go.Scatter(
                x=[pos[node][0] for node in subnet_nodes],
                y=[pos[node][1] for node in subnet_nodes],
                mode='markers+text',
                text=[self.graph.nodes[node]['label'] for node in subnet_nodes],
                textposition="top center",
                marker=dict(
                    size=20,
                    color='lightblue',
                    symbol='square'
                ),
                name='Subnets'
            )
            node_traces.append(subnet_trace)
        
        # Host nodes by device type
        device_colors = {
            'router': 'red',
            'firewall': 'orange',
            'server': 'green',
            'workstation': 'blue',
            'printer': 'purple',
            'unknown': 'gray'
        }
        
        for device_type, color in device_colors.items():
            device_nodes = [
                n for n, d in self.graph.nodes(data=True) 
                if d.get('type') == 'host' and d.get('device_type', 'unknown') == device_type
            ]
            if device_nodes:
                device_trace = go.Scatter(
                    x=[pos[node][0] for node in device_nodes],
                    y=[pos[node][1] for node in device_nodes],
                    mode='markers',
                    marker=dict(
                        size=10,
                        color=color
                    ),
                    name=device_type.title(),
                    text=[self.graph.nodes[node]['label'] for node in device_nodes],
                    hovertemplate='%{text}<extra></extra>'
                )
                node_traces.append(device_trace)
        
        # Create figure
        fig = go.Figure(data=[edge_trace] + node_traces,
                       layout=go.Layout(
                           title=title,
                           showlegend=True,
                           hovermode='closest',
                           margin=dict(b=20, l=5, r=5, t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           plot_bgcolor='white'
                       ))
        
        # Save to file
        fig.write_html(output_file)
        return fig
    
    def generate_matplotlib_visualization(self, output_file: str):
        """Generate static matplotlib visualization"""
        plt.figure(figsize=(12, 8))
        
        # Position nodes
        pos = nx.spring_layout(self.graph, k=2, iterations=50)
        
        # Draw different node types
        subnet_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('type') == 'subnet']
        host_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('type') == 'host']
        
        # Draw edges
        nx.draw_networkx_edges(self.graph, pos, alpha=0.3)
        
        # Draw subnet nodes
        if subnet_nodes:
            nx.draw_networkx_nodes(self.graph, pos, 
                                 nodelist=subnet_nodes,
                                 node_color='lightblue',
                                 node_shape='s',
                                 node_size=1000)
        
        # Draw host nodes
        if host_nodes:
            # Color by device type
            node_colors = []
            for node in host_nodes:
                device_type = self.graph.nodes[node].get('device_type', 'unknown')
                color_map = {
                    'router': 'red',
                    'firewall': 'orange', 
                    'server': 'green',
                    'workstation': 'blue',
                    'printer': 'purple',
                    'unknown': 'gray'
                }
                node_colors.append(color_map.get(device_type, 'gray'))
            
            nx.draw_networkx_nodes(self.graph, pos,
                                 nodelist=host_nodes,
                                 node_color=node_colors,
                                 node_size=300)
        
        # Add labels
        labels = {n: d.get('label', n)[:15] for n, d in self.graph.nodes(data=True)}
        nx.draw_networkx_labels(self.graph, pos, labels, font_size=8)
        
        plt.title("Network Topology Map")
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        plt.close()
