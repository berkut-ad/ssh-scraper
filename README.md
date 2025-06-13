# Network Device Auditor & Command Executor

This Python script is designed to **automate the discovery, auditing, and command execution** across a fleet of network devices using **NAPALM** and **Netmiko**. It supports multivendor environments including Cisco, Arista, and Juniper with flexible credential and command configuration via YAML files.

The python script runs per-vendor/per-device-type command sets (stored in a commands.yaml file) and can be used to
 
Detect vendor and model/type.
I wanted to made the code generic and not limit it to just Aristas. The first iteration of code had me manually parsing the ouptput of "show version" and "show system-info" to get details of vendor and device type etc but then while researching I came across packages - Netmiko and Napalm that can do it. However, I did realize that it didnt work on my Python version of 3.12 and requires 3.8. I then ran it in a virtual environment using pyenv. I am considering if I should even use the package anymore.
Match to the correct command list from commands.yaml.
Run those commands via SSH.
Save the output to a per-device log file (e.g., logs/10.1.1.1.txt).
Use NAPALM for probing (vendor, model, uptime, version).
Use Netmiko for running command sets.
Reuse credentials.yaml, commands.yaml, and ip_list.txt.

---

## Features

- Auto-detects platform/vendor using NAPALM facts (if supported)
- Intelligent fallback: 
  - Uses NAPALM when available (e.g., Arista eAPI, Cisco, Juniper)
  - Skips NAPALM when Arista uses SSH (avoids NAPALM authentication failures)
- Supports both password and SSH key authentication
- Multithreaded execution for scalability
- Logs output per device + consolidated CSV and JSON summaries
- Structured configuration using YAML (for IPs, credentials, commands)

---

# Logic

- Reads list of target IPs
- Attempts NAPALM probe to determine vendor/model/OS (unless skipped)
- Uses mapped platform (e.g. cisco_ios, arista_eos) for Netmiko
- Loads applicable command list from commands.yaml
- Executes commands and stores output under logs/<device>.txt
- Exports summary to summary.csv and summary.json

# Special Handling for Arista
If optional_args.transport is ssh, NAPALM is skipped (as it requires eAPI).
If transport is https, NAPALM will attempt connection using eAPI.

## PIP requirements and Dependencies

Install dependencies using:

pyenv activate napalm-env
deactivate
pip install napalm
pip install tabulate
pip install colorama

| Library              | Purpose                              |
| -------------------- | ------------------------------------ |
| `napalm`             | Device platform abstraction & facts  |
| `netmiko`            | SSH command execution                |
| `paramiko`           | Underlying SSH library for transport |
| `PyYAML`             | Parsing `.yaml` files                |
| `tabulate`           | Pretty-printing result tables        |
| `concurrent.futures` | Threaded parallelism                 |
| `logging`            | Log device activity/debugging        |

# File structure format
```
.
├── scraper.py              # Main script
├── ip_list.txt             # Input:List of target device IPs
├── credentials.yaml        # Input: Credentials & auth method per device
├── commands.yaml           # Input: Vendor/Device-type command templates
├── logs/                   # Output: Per-device log output
├── summary.csv             # Output: Tabular audit result
├── summary.json            # Output: JSON audit result
└── network_probe.log       # Output: Debug and execution log
```
# Example Execution

``` bash
python scraper.py \
    --ip-file ip_list.txt \
    --credentials credentials.yaml \
    --commands commands.yaml \
    --threads 10 \
    --debug

```
Flags:

```
--debug: Enables verbose logging in network_probe.log
--threads: Run up to N devices in parallel
```

# Sample table output

| ip         | platform | vendor | model       | version   | uptime     | status  |
|------------|----------|--------|-------------|-----------|------------|---------|
| 10.10.10.1 | eos      | Arista | DCS-7050QX  | 4.23.1F   | 240 hours  | Success |
| 10.10.10.2 | ios      | Cisco  | WS-C3850-48 | 16.6.4    | 500 hours  | Success |

# Why NAPALM doesnt work for Arista SSH-key based auth.
NAPALM’s Arista eos driver uses pyeapi by default, not Netmiko or Paramiko directly. And pyeapi does not support SSH key-based auth unless you're connecting over HTTPS with eAPI enabled on the device. That's why it's falling back to keyboard-interactive and failing.

# NAPALM EOS version limits
Use with Versions below 4.23.0 for Arista EOS comment out lines 227 and 228 in napalm library
in the class - napalm > eos > eos.py > class EOSDriver(NetworkDriver):
 
        # if self._eos_version < EOSVersion("4.23.0"):
        #    raise UnsupportedVersion(self._eos_version)

# NAPALM General Support Matrix

|                | EOS      | Junos      | IOS-XR (NETCONF) | IOS-XR (XML-Agent) | NX-OS    | NX-OS SSH | IOS        |
|----------------|----------|------------|------------------|--------------------|----------|-----------|------------|
| **Driver Name**      | eos      | junos      | iosxr_netconf     | iosxr              | nxos     | nxos_ssh  | ios        |
| **Structured data**  | Yes      | Yes        | Yes              | No                 | Yes      | No        | No         |
| **Minimum version**  | 4.15.0F  | 12.1       | 7                | 5.1.0              | 6.1 [1]  | 6.3.2     | 12.4(20)T  |
| **Backend library**  | pyeapi   | junos-eznc | ncclient         | pyIOSXR            | pynxos   | netmiko   | netmiko    |


# NAPALM CLI commands.
```
napalm --debug --vendor eos --user admin --password Ar1sta --optional_args "transport=http" 10.10.10.1 call get_facts
napalm --debug --vendor eos --user admin --password Password@123 --optional_args transport=\"http\" 10.10.10.1 call get_facts
```
# Use of curl to test if eAPI is working on Arista. 

``` bash
$ curl -k -u admin:Password@123   -H "Content-Type: application/json"   -X POST   https://10.10.10.1/command-api   -d '{
    "jsonrpc": "2.0",
    "method": "runCmds",
    "params": {
      "version": 1,
      "cmds": ["show version"],
      "format": "json"
    },
    "id": "1"
  }'
```



 