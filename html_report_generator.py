import os
import re
import difflib
import json
from collections import defaultdict

LOG_DIR = 'logs'
OUTPUT_HTML = 'report.html'
OUTPUT_JSON = 'report_data.json'

# Parse logs: extract command/output pairs
def parse_log_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    matches = re.split(r"\n>> (.+?)\n", content)[1:]
    commands = {}
    for i in range(0, len(matches), 2):
        cmd = matches[i].strip()
        output = matches[i + 1].strip()
        commands[cmd] = output
    return commands

# Collect device outputs
device_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".txt")]
device_outputs = {}
for fname in device_files:
    ip = fname.split("_")[0]
    filepath = os.path.join(LOG_DIR, fname)
    device_outputs[ip] = parse_log_file(filepath)

# Invert structure: command -> device -> output
command_data = defaultdict(dict)
for ip, commands in device_outputs.items():
    for cmd, output in commands.items():
        command_data[cmd][ip] = output

# Generate static HTML diff using Python's difflib
html_sections = []
for cmd, ip_map in command_data.items():
    ips = list(ip_map.keys())
    ref_ip = ips[0]
    ref_output = ip_map[ref_ip].splitlines()

    section = f'<details open><summary><strong>{cmd}</strong></summary>'
    section += f'<p>Comparing all devices to reference: <code>{ref_ip}</code></p>'

    table_rows = ""
    for ip in ips:
        output_lines = ip_map[ip].splitlines()
        diff = difflib.HtmlDiff(wrapcolumn=120).make_table(
            ref_output,
            output_lines,
            fromdesc=f"{ref_ip}",
            todesc=f"{ip}",
            context=True,
            numlines=3
        )
        table_rows += f'<h4>{ref_ip} vs {ip}</h4>{diff}<br>'

    section += table_rows + '</details><hr>'
    html_sections.append(section)

html_body = "\n".join(html_sections)

# HTML template with embedded styles and search/dark mode toggle
html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Device Command Diff Report</title>
  <style>
    body {{ font-family: sans-serif; background: #fff; color: #000; margin: 2em; }}
    .dark-mode {{ background-color: #1e1e1e; color: #e0e0e0; }}
    button {{ margin-right: 1em; }}
    table.diff {{ width: 100%; font-family: monospace; border-collapse: collapse; margin-bottom: 2em; }}
    .diff_header {{ background-color: #f7f7f7; font-weight: bold; }}
    .diff_next {{ background-color: #f0f0f0; }}
    .diff_add {{ background-color: #dfd; }}
    .diff_chg {{ background-color: #fd7; }}
    .diff_sub {{ background-color: #fdd; }}
    input[type="search"] {{ padding: 5px; width: 300px; }}
  </style>
</head>
<body>
  <button onclick="toggleDarkMode()">Toggle Dark Mode</button>
  <input type="search" id="searchBox" placeholder="Search commands or IPs..." onkeyup="search()" />
  <div id="report">
    {html_body}
  </div>

<script>
function toggleDarkMode() {{
  document.body.classList.toggle('dark-mode');
}}
function search() {{
  let query = document.getElementById('searchBox').value.toLowerCase();
  let sections = document.querySelectorAll('details');
  sections.forEach(section => {{
    let text = section.innerText.toLowerCase();
    section.style.display = text.includes(query) ? '' : 'none';
  }});
}}
</script>
</body>
</html>
"""

# Save report and data
with open(OUTPUT_HTML, 'w') as f:
    f.write(html_template)

with open(OUTPUT_JSON, 'w') as f:
    json.dump(command_data, f, indent=2)

print(f"Generated HTML diff report: {OUTPUT_HTML}")
