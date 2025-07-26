#!/usr/bin/env python3
#
# Enhanced Reconnaissance Automation Script v4.1
# Fixed global variable handling and improved error resilience
#
import subprocess
import os
import sys
import argparse
import ipaddress
import json
import re
import time
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import shlex

# --- Configuration ---
DEFAULT_PORTS = "80,443,8080,8443"
MASSCAN_RATE = 1000
DEFAULT_THREADS = 10  # Renamed to avoid conflict
OUTPUT_DIR = "recon_results"
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8088, 8888}

# --- Helpers ---
def print_banner(threads):
    print("="*60)
    print("  Enhanced Recon Automation Script v4.1")
    print(f"  Threads: {threads} | Ports: {DEFAULT_PORTS}")
    print("="*60)
    print(f"[*] Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def sanitize_domain(domain):
    """Remove potentially dangerous characters from domain input"""
    return re.sub(r'[^a-zA-Z0-9.\-]', '', domain)

def check_tool(tool):
    if not shutil.which(tool):
        print(f"[ERROR] {tool} not found. Install it and retry.")
        sys.exit(1)
    print(f"[OK] {tool} present")

def write_targets(targets, filename):
    with open(filename, 'w') as f:
        for target in targets:
            f.write(f"{target}\n")

# --- Core Functions ---
def run_command(cmd, tool_name):
    """Execute command safely without shell=True"""
    try:
        result = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] {tool_name} failed: {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        print(f"[ERROR] {tool_name} not installed")
        return None

def enum_subdomains(target, output_dir, tools, threads):
    out_file = os.path.join(output_dir, f"{target}_subdomains.txt")
    results = set()
    
    print(f"[*] Enumerating subdomains for {target}...")
    for tool in tools:
        if tool == 'sublist3r':
            cmd = f"sublist3r -d {target} -o {out_file}"
            run_command(cmd, "Sublist3r")
        elif tool == 'amass':
            cmd = f"amass enum -d {target} -o {out_file}.amass"
            run_command(cmd, "Amass")
        elif tool == 'assetfinder':
            cmd = f"assetfinder {target} > {out_file}.assetfinder"
            run_command(cmd, "Assetfinder")
    
    # Combine results from all tools
    for tool_file in [out_file, f"{out_file}.amass", f"{out_file}.assetfinder"]:
        if os.path.exists(tool_file):
            with open(tool_file) as f:
                results.update(line.strip() for line in f if line.strip())
    
    with open(out_file, 'w') as f:
        for d in sorted(results): 
            f.write(d + "\n")
            
    return list(results)

def run_port_scan(targets, ports, config):
    """Perform port scanning with Masscan/Nmap integration"""
    use_masscan = config.get('use_masscan', False)
    threads = config['threads']
    print(f"[*] Scanning {len(targets)} targets on ports: {ports}")
    target_file = os.path.join(OUTPUT_DIR, "targets.txt")
    write_targets(targets, target_file)
    
    # Masscan discovery
    masscan_results = set()
    if use_masscan:
        masscan_rate = config.get('masscan_rate', MASSCAN_RATE)
        masscan_out = target_file + ".masscan"
        cmd = f"masscan -iL {target_file} -p {ports} --rate={masscan_rate} -oL {masscan_out}"
        if run_command(cmd, "Masscan"):
            with open(masscan_out) as f:
                for line in f:
                    if line.startswith('open tcp'):
                        parts = line.split()
                        masscan_results.add((parts[3], int(parts[2])))
    
    # Nmap detailed scan
    nmap_out = target_file + ".nmap"
    timing = config.get('nmap_timing', '-T3')
    nmap_cmd = f"nmap {timing} -sS -p {ports} --open -iL {target_file} -oG {nmap_out} -oX {nmap_out}.xml"
    run_command(nmap_cmd, "Nmap")
    
    # Parse Nmap results
    host_ports = {}
    with open(nmap_out) as f:
        for line in f:
            if 'Status: Up' in line and '/open/' in line:
                parts = line.split()
                ip = parts[1]
                ports = [int(p.split('/')[0]) for p in parts[4:] if '/open/' in p]
                host_ports[ip] = ports
                
    return host_ports

def check_web_service(host_port):
    """Check HTTP/HTTPS service on a specific host:port"""
    host, port = host_port
    schemes = ['https'] if port in {443, 8443} else ['http']
    
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
        try:
            response = requests.head(
                url, 
                timeout=3, 
                allow_redirects=True,
                headers={'User-Agent': 'ReconScript/4.1'}
            )
            if response.status_code < 400:
                return {
                    'url': url,
                    'status': response.status_code,
                    'headers': dict(response.headers)
                }
        except (requests.exceptions.RequestException, ValueError):
            continue
    return None

# --- Main Modes ---
def run_domain_scan(domains, config):
    results = {}
    tools = config.get('enum_tools', ['sublist3r'])
    ports = config['ports']
    threads = config['threads']
    
    # Subdomain enumeration
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {
            executor.submit(enum_subdomains, sanitize_domain(d), OUTPUT_DIR, tools, threads): d 
            for d in domains
        }
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            results[domain] = {
                'subdomains': future.result(),
                'services': {}
            }
    
    # Port scanning
    all_targets = []
    for domain_data in results.values():
        all_targets.extend(domain_data['subdomains'])
    
    host_ports = run_port_scan(
        all_targets, 
        ports, 
        config
    )
    
    # HTTP service checks
    web_targets = []
    for host, ports in host_ports.items():
        for port in ports:
            if port in WEB_PORTS:
                web_targets.append((host, port))
    
    with ThreadPoolExecutor(max_workers=threads*2) as executor:
        future_to_target = {
            executor.submit(check_web_service, target): target 
            for target in web_targets
        }
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            service_info = future.result()
            if service_info:
                host, port = target
                results.setdefault('services', {})[f"{host}:{port}"] = service_info
    
    return results

def run_cidr_scan(cidr, config):
    """Scan IP network range"""
    net = ipaddress.ip_network(cidr)
    targets = [str(ip) for ip in net.hosts()]
    ports = config['ports']
    threads = config['threads']
    
    print(f"[*] Scanning {cidr} ({len(targets)} hosts)")
    host_ports = run_port_scan(
        targets, 
        ports, 
        config
    )
    
    # HTTP service checks
    web_targets = []
    for host, ports in host_ports.items():
        for port in ports:
            if port in WEB_PORTS:
                web_targets.append((host, port))
    
    services = {}
    with ThreadPoolExecutor(max_workers=threads*2) as executor:
        future_to_target = {
            executor.submit(check_web_service, target): target 
            for target in web_targets
        }
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            service_info = future.result()
            if service_info:
                host, port = target
                services[f"{host}:{port}"] = service_info
    
    return {
        'cidr': cidr,
        'host_count': len(targets),
        'services': services
    }

# --- CLI & Config ---
def main():
    parser = argparse.ArgumentParser(
        description="Advanced Reconnaissance Automation Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-d', '--domains', help="Comma-separated domain list")
    parser.add_argument('-c', '--cidr', help="CIDR range to scan")
    parser.add_argument('-p', '--ports', default=DEFAULT_PORTS, 
                        help="Ports to scan (comma-separated)")
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS,
                        help="Concurrency level")
    parser.add_argument('--masscan', action='store_true',
                        help="Use Masscan for initial discovery")
    parser.add_argument('--http-check', action='store_true', default=True,
                        help="Perform HTTP service validation")
    parser.add_argument('--tools', default='sublist3r,amass',
                        help="Subdomain tools (comma-separated)")
    parser.add_argument('--web-ports', default=','.join(map(str, WEB_PORTS)),
                        help="Ports to consider for HTTP checks")
    parser.add_argument('--continuous', type=int, metavar='MINUTES',
                        help="Continuous mode with interval in minutes")
    parser.add_argument('--mode', choices=['stealth', 'normal', 'aggressive'], 
                        default='normal', help="Scan aggressiveness profile")
    parser.add_argument('--examples', action='store_true',
                        help="Show usage examples")
    
    args = parser.parse_args()
    
    if args.examples:
        print("\nUsage Examples:")
        print("  Basic domain scan: ./recon.py -d example.com")
        print("  CIDR scan with Masscan: ./recon.py -c 192.168.0.0/24 --masscan")
        print("  Custom ports: ./recon.py -d example.com -p 80,443,8080")
        print("  Continuous mode: ./recon.py -d example.com --continuous 60")
        print("  Aggressive mode: ./recon.py -d example.com --mode aggressive")
        sys.exit(0)
    
    # Configuration setup
    config = {
        'ports': args.ports,
        'threads': args.threads,
        'use_masscan': args.masscan,
        'http_check': args.http_check,
        'enum_tools': args.tools.split(','),
        'mode': args.mode
    }
    
    # Set parameters based on mode
    if config['mode'] == 'aggressive':
        config['masscan_rate'] = 10000
        config['nmap_timing'] = '-T4'
    elif config['mode'] == 'stealth':
        config['masscan_rate'] = 100
        config['nmap_timing'] = '-T2'
    else:  # normal
        config['masscan_rate'] = 1000
        config['nmap_timing'] = '-T3'
    
    # Update web ports
    WEB_PORTS.update(map(int, args.web_ports.split(',')))
    
    # Continuous mode handler
    def execute_scan():
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Tool validation
        required_tools = {'nmap', *config['enum_tools']}
        if config['use_masscan']: required_tools.add('masscan')
        for tool in required_tools: check_tool(tool)
        
        print_banner(config['threads'])
        
        if args.domains:
            domains = [sanitize_domain(d) for d in args.domains.split(',')]
            results = run_domain_scan(domains, config)
        elif args.cidr:
            results = run_cidr_scan(args.cidr, config)
        else:
            print("[ERROR] Specify either domains or CIDR range")
            sys.exit(1)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(OUTPUT_DIR, f"results_{timestamp}.json")
        with open(out_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results saved to {out_file}")
    
    if args.continuous:
        print(f"[*] Starting continuous mode (interval: {args.continuous} minutes)")
        while True:
            execute_scan()
            print(f"[*] Sleeping for {args.continuous} minutes...")
            time.sleep(args.continuous * 60)
    else:
        execute_scan()

if __name__ == '__main__':
    main()
