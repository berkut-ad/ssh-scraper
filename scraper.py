import os
import yaml
import csv
import json
import logging
import argparse
from collections import defaultdict
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from napalm import get_network_driver
from colorama import Fore, Style, init as colorama_init
from datetime import datetime

LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger(__name__)


def setup_logging(debug=False):
    # Initialize colorama
    colorama_init()

    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_level = logging.DEBUG if debug else logging.INFO

    # Clear existing handlers to prevent duplicate logs
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = []

    # File handler
    file_handler = logging.FileHandler('network_probe.log', mode='w')
    file_formatter = logging.Formatter(log_format)
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(log_level)
    root_logger.addHandler(file_handler)

    # Colored console handler
    class ColorFormatter(logging.Formatter):
        COLORS = {
            logging.DEBUG: Fore.CYAN,
            logging.INFO: Fore.GREEN,
            logging.WARNING: Fore.YELLOW,
            logging.ERROR: Fore.RED,
            logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
        }

        def format(self, record):
            color = self.COLORS.get(record.levelno, "")
            reset = Style.RESET_ALL
            message = super().format(record)
            return f"{color}{message}{reset}"

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorFormatter(log_format))
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)


def load_yaml_file(filename):
    with open(filename) as f:
        return yaml.safe_load(f)


def read_ip_file(filename):
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]


def detect_vendor_with_netmiko(ip, creds, platform_hint='arista_eos'):
    logger.info(f"[{ip}] Attempting vendor detection using Netmiko.")

    conn_params = {
        'device_type': platform_hint,  # e.g., arista_eos
        'host': ip,
        'username': creds['username'],
    }

    if creds.get('auth_method') == 'ssh_key':
        conn_params['use_keys'] = True
        conn_params['key_file'] = creds.get('ssh_key_file')
    else:
        conn_params['password'] = creds.get('password')

    if 'secret' in creds:
        conn_params['secret'] = creds['secret']

    try:
        conn = ConnectHandler(**conn_params)
        if not platform_hint.startswith("arista"):
            conn.enable()

        logger.info(f"[{ip}] Connected successfully for vendor detection.")
        output = conn.send_command("show version", use_textfsm=True)

        # TextFSM helps parse output (if available)
        logger.debug(f"[{ip}] 'show version' output: {output}")

        vendor = "Unknown"
        model = "-"
        version = "-"
        uptime = "-"
        if isinstance(output, list) and output:
            output = output[0]  # Use the first parsed entry
            vendor = output.get('vendor', 'Unknown')
            model = output.get('hardware', ['-'])[0]
            version = output.get('version', '-')
        else:
            raw = conn.send_command("show version")
            if "Cisco" in raw:
                vendor = "Cisco"
            elif "Arista" in raw:
                vendor = "Arista"
            elif "Juniper" in raw:
                vendor = "Juniper"
            elif "Palo Alto" in raw or "PA-" in raw:
                vendor = "Palo Alto"
            version = "unknown"

        conn.disconnect()

        return {
            'vendor': vendor,
            'model': model,
            'version': version,
            'uptime': uptime,
            'status': 'Detected via Netmiko'
        }

    except Exception as e:
        logger.error(f"[{ip}] Vendor detection with Netmiko failed: {e}")
        return {
            'vendor': '-',
            'model': '-',
            'version': '-',
            'uptime': '-',
            'status': f"Netmiko Detection Failed: {e}"
        }


def get_platform_mapping(vendor):
    vendor = vendor.lower()
    if "cisco" in vendor:
        return "cisco_ios"
    elif "juniper" in vendor:
        return "juniper"
    elif "arista" in vendor:
        return "arista_eos"
    elif "palo alto" in vendor or "paloalto" in vendor:
        return "paloalto_panos"
    return "generic"


def probe_device_with_napalm(ip, creds):
    logger.info(f"[{ip}] Starting NAPALM probe.")

    try:
        # Detect if Arista and SSH transport (eAPI not available)
        if (creds.get('auth_method') == 'ssh_key') and creds.get('optional_args', {}).get('transport', '') == 'ssh':
            logger.info(f"[{ip}] SSH key-based auth detected with SSH transport — testing if device is Arista.")
            # Try to detect Arista from the IP (optional pre-logic), or proceed to fallback after NAPALM
            return {
                'ip': ip,
                'platform': 'arista_eos',
                'vendor': 'Arista',
                'model': '-',
                'version': '-',
                'uptime': '-',
                'device_type': 'Default',
                'status': 'Proceed'
            }

        for driver_name in ['eos', 'ios', 'nxos', 'junos', 'panos']:
            try:
                logger.debug(f"[{ip}] Trying NAPALM driver: {driver_name}")
                driver = get_network_driver(driver_name)

                optional_args = creds.get('optional_args', {})
                device = driver(
                    hostname=ip,
                    username=creds['username'],
                    password=creds.get('password', ''),
                    optional_args=optional_args
                )
                device.open()
                facts = device.get_facts()
                logger.debug(f"[{ip}] NAPALM facts received: {facts}")
                if not facts:
                    logger.warning(f"[{ip}] No facts returned by NAPALM driver {driver_name}.")
                    device.close()
                    continue
                device.close()

                vendor = facts.get("vendor", "").lower()
                model = facts.get("model", "").lower()
                hostname = facts.get("hostname", "").lower()
                os_version = facts.get("os_version", "").lower()

                if "arista" in vendor or "veos" in model or "eos" in os_version or "arista" in hostname:
                    platform = "arista_eos"
                    vendor_name = "Arista"
                elif "cisco" in vendor or "ios" in os_version:
                    platform = "cisco_ios"
                    vendor_name = "Cisco"
                elif "juniper" in vendor or "junos" in os_version:
                    platform = "juniper"
                    vendor_name = "Juniper"
                elif "palo alto" in vendor or "panos" in os_version:
                    platform = "paloalto_panos"
                    vendor_name = "Palo Alto"
                else:
                    platform = None
                    vendor_name = vendor or "Unknown"

                logger.info(f"[{ip}] NAPALM probe successful with {driver_name}.")
                return {
                    'ip': ip,
                    'platform': platform,
                    'vendor': vendor_name,
                    'model': facts['model'],
                    'version': facts['os_version'],
                    'uptime': f"{facts['uptime'] // 3600} hours",
                    'device_type': 'Default',
                    'status': 'Success'
                }

            except Exception as e:
                logger.debug(f"[{ip}] NAPALM driver {driver_name} failed: {e}")
                continue

        logger.warning(f"[{ip}] No working NAPALM driver found.")
        return {
            'ip': ip,
            'vendor': '-',
            'model': '-',
            'version': '-',
            'uptime': '-',
            'device_type': '-',
            'status': 'Unrecognized platform'
        }

    except Exception as e:
        logger.error(f"[{ip}] NAPALM probe error: {e}")
        return {
            'ip': ip,
            'vendor': '-',
            'model': '-',
            'version': '-',
            'uptime': '-',
            'device_type': '-',
            'status': f"NAPALM Error: {str(e)}"
        }


def get_command_list(commands_data, vendor, device_type='Default'):
    vendor_cmds = commands_data.get(vendor, {})
    return vendor_cmds.get(device_type, vendor_cmds.get("Default", []))


def run_commands_with_netmiko(ip, creds, platform, commands):
    logger.info(f"[{ip}] Connecting with Netmiko ({platform})")
    log_output = ""

    try:
        conn_params = {
            'device_type': platform,
            'host': ip,
            'username': creds['username'],
        }

        if creds.get('auth_method') == 'ssh_key':
            conn_params['use_keys'] = True
            conn_params['key_file'] = creds.get('ssh_key_file')
        else:
            conn_params['password'] = creds.get('password')

        if 'secret' in creds:
            conn_params['secret'] = creds['secret']
        
        logger.debug(f"[{ip}] Platform: {platform}, Cred keys: {list(creds.keys())}")
        logger.debug(f"[{ip}] Using secret: {conn_params.get('secret')}")

        conn = ConnectHandler(**conn_params)
        logger.debug(f"[{ip}] Connection parameters: {conn_params}")
        # Enter enable mode if secret is provided
        if not platform.startswith("arista"):
            conn.enable()
        logger.info(f"[{ip}] Connected successfully with Netmiko.")
        log_output += f"Connected to {ip} with Netmiko ({platform})\n"

        for cmd in commands:
            try:
                out = conn.send_command(cmd)
                logger.info(f"[{ip}] Ran command: {cmd}")
                log_output += f"\n>> {cmd}\n{out}\n"
            except Exception as e:
                logger.error(f"[{ip}] Error running command '{cmd}': {e}")
                log_output += f"\n>> {cmd}\nERROR: {str(e)}\n"

        conn.disconnect()
    except Exception as e:
        logger.error(f"[{ip}] Netmiko connection error: {e}")
        log_output += f"\nConnection error: {str(e)}\n"

    return log_output


def process_device(ip, creds, commands_data):
    logger.info(f"[{ip}] Processing started.")
    result = probe_device_with_napalm(ip, creds)

    if result['status'] not in ['Success', 'Proceed']:
        logger.warning(f"[{ip}] NAPALM did not run successfully. Attempting fallback detection with Netmiko.")
        fallback = detect_vendor_with_netmiko(ip, creds)
        result.update(fallback)
        if fallback['vendor'] == '-' or fallback['status'].startswith("Netmiko Detection Failed"):
            return result  # Skip further if detection fails

    vendor = result['vendor']
    platform = get_platform_mapping(vendor)
    commands = get_command_list(commands_data, vendor)

    logger.info(f"[{ip}] Running commands for vendor: {vendor}, platform: {platform}")
    log_output = f"Device: {ip}\nVendor: {vendor}\nModel: {result['model']}\nVersion: {result['version']}\nUptime: {result['uptime']}\n\n"

    command_output = run_commands_with_netmiko(ip, creds, platform, commands)
    log_output += command_output
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    logfile = os.path.join(LOG_DIR, f"{ip}_{timestamp}.txt")
    with open(logfile, 'w') as f:
        f.write(log_output)
        logger.info(f"[{ip}] Log written to {logfile}")

    return result


def export_results(results):
    with open('summary.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    with open('summary.json', 'w') as f:
        json.dump(results, f, indent=4)


def main():
    parser = argparse.ArgumentParser(description="Network Device Prober & Auditor")
    parser.add_argument('--ip-file', default='ip_list.txt', help='File containing list of IPs')
    parser.add_argument('--credentials', default='credentials.yaml', help='Credentials YAML file')
    parser.add_argument('--commands', default='commands.yaml', help='Commands YAML file')
    parser.add_argument('--threads', type=int, default=10, help='Number of parallel threads')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()
    setup_logging(args.debug)

    logger.info("Script started with arguments: %s", args)

    ip_list = read_ip_file(args.ip_file)
    creds_yaml = load_yaml_file(args.credentials)
    commands_data = load_yaml_file(args.commands)

    default_creds = creds_yaml.get('default', {})
    device_creds = creds_yaml.get('devices', {})

    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                process_device,
                ip,
                device_creds.get(ip, default_creds),
                commands_data
            ): ip for ip in ip_list
        }

        for future in as_completed(futures):
            result = future.result()
            logger.info(f"Completed device: {result['ip']} - Status: {result['status']}")
            results.append(result)

    print(tabulate(results, headers='keys', tablefmt='grid'))
    export_results(results)
    logger.info("Script completed.")


if __name__ == '__main__':
    main()
