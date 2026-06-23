# SSH Log Alert Tool

This is a small cybersecurity project I made for checking SSH login logs. The idea is simple: read an auth log file, look for failed login attempts, and create alerts when the same IP address keeps trying too many times.

I used SSH logs because brute-force login attempts are common in real systems, and this is something a SOC analyst would normally monitor.

## What it checks

- Failed SSH login attempts
- Invalid usernames like `admin`, `test`, `guest`, etc.
- A successful login that happens after many failed attempts
- Repeated failures from the same IP address in a short time

## Files

```text
soc-log-detection-prototype/
|-- config/
|   `-- detection_rules.json
|-- data/
|   `-- sample_auth.log
|-- reports/
|-- src/
|   `-- soc_log_detector.py
|-- requirements.txt
`-- README.md
```

## How to run

Open a terminal in this folder and run:

```bash
python src/soc_log_detector.py --log-file data/sample_auth.log --config config/detection_rules.json
```

After running it, check the `reports` folder.

The program creates:

- `alerts.json`
- `summary.txt`

## Rules used

The rules are stored in `config/detection_rules.json`.

Right now, an IP is marked as suspicious if it has 5 failed logins within 10 minutes. This can be changed from the JSON file without editing the Python code.

## Why this project is useful

In a real SOC, analysts cannot manually read every log line. A small script like this can help filter the important events first. It is not a full SIEM tool, but it shows the basic idea behind log monitoring and alert generation.

## Possible improvements

- Add support for more log formats
- Monitor logs live instead of only reading a file
- Send alerts by email
- Add IP reputation checking
- Make a simple dashboard
