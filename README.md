The python script runs per-vendor/per-device-type command sets (stored in a commands.yaml file) and can be used to
 
Detect vendor and model/type.
I wanted to made the code generic and not limit it to just Aristas. The first iteration of code had me manually parsing the ouptput of "show version" and "show system-info" to get details of vendor and device type etc but then while researching I came across packages - Netmiko and Napalm that can do it. However, I did realize that it didnt work on my Python version of 3.12 and requires 3.8. I then ran it in a virtual environment using pyenv. I am considering if I should even use the package anymore.
Match to the correct command list from commands.yaml.
Run those commands via SSH.
Save the output to a per-device log file (e.g., logs/10.1.1.1.txt).
Use NAPALM for probing (vendor, model, uptime, version).
Use Netmiko for running command sets.
Reuse credentials.yaml, commands.yaml, and ip_list.txt.

COMMANDS

pyenv activate napalm-env
deactivate
pip install paramiko pyyaml textfsm
pip install netmiko napalm
pip install napalm-eos napalm-junos napalm-ios


NAPALM’s Arista eos driver uses pyeapi by default, not Netmiko or Paramiko directly. And pyeapi does not support SSH key-based auth unless you're connecting over HTTPS with eAPI enabled on the device. That's why it's falling back to keyboard-interactive and failing.