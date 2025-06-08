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

LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger(__name__)


def setup_logging(debug=False):
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        filename='network_probe.log',
        filemode='w',
        level=logging.DEBUG if debug else logging.INFO,
        format=log_format
    )
    if debug:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(log_format)
        console.setFormatter(formatter)
        logging.getLogger().addHandler(console)


def load_yaml_file(filename):
    with open(filename) as f:
        return yaml.safe_load(f)


def read_ip_file(filename):
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]


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

    if result['status'] != 'Success':
        logger.warning(f"[{ip}] Skipping command run due to NAPALM failure.")
        return result

    vendor = result['vendor']
    platform = get_platform_mapping(vendor)
    commands = get_command_list(commands_data, vendor)

    logger.info(f"[{ip}] Running commands for vendor: {vendor}, platform: {platform}")
    log_output = f"Device: {ip}\nVendor: {vendor}\nModel: {result['model']}\nVersion: {result['version']}\nUptime: {result['uptime']}\n\n"

    command_output = run_commands_with_netmiko(ip, creds, platform, commands)
    log_output += command_output

    logfile = os.path.join(LOG_DIR, f"{ip}.txt")
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
