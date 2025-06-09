The python script runs per-vendor/per-device-type command sets (stored in a commands.yaml file) and can be used to
 
Detect vendor and model/type.
I wanted to made the code generic and not limit it to just Aristas. The first iteration of code had me manually parsing the ouptput of "show version" and "show system-info" to get details of vendor and device type etc but then while researching I came across packages - Netmiko and Napalm that can do it. However, I did realize that it didnt work on my Python version of 3.12 and requires 3.8. I then ran it in a virtual environment using pyenv. I am considering if I should even use the package anymore.
Match to the correct command list from commands.yaml.
Run those commands via SSH.
Save the output to a per-device log file (e.g., logs/10.1.1.1.txt).
Use NAPALM for probing (vendor, model, uptime, version).
Use Netmiko for running command sets.
Reuse credentials.yaml, commands.yaml, and ip_list.txt.

# PIP requirements

pyenv activate napalm-env
deactivate
pip install napalm
pip install tabulate

# Why NAPALM doesnt work for Arista SSH-key based auth.
NAPALM’s Arista eos driver uses pyeapi by default, not Netmiko or Paramiko directly. And pyeapi does not support SSH key-based auth unless you're connecting over HTTPS with eAPI enabled on the device. That's why it's falling back to keyboard-interactive and failing.

# Use with Versions below 4.23.0 for Arista EOS comment out lines 227 and 228 in napalm library
# in the class - napalm > eos > eos.py > class EOSDriver(NetworkDriver):
 
        #if self._eos_version < EOSVersion("4.23.0"):
        #    raise UnsupportedVersion(self._eos_version)

# NAPALM CLI commands.
napalm --debug --vendor eos --user admin --password Ar1sta --optional_args "transport=http" 10.10.10.1 call get_facts
napalm --debug --vendor eos --user admin --password Password@123 --optional_args transport=\"http\" 10.10.10.1 call get_facts

# Use of curl to test if eAPI is working on Arista. 

'```
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



 