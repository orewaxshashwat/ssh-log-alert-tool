import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


failed_login_regex = re.compile(
    r"^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: "
    r"Failed password for (?:(?P<invalid>invalid user) )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

success_login_regex = re.compile(
    r"^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: "
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def read_rules(config_file):
    with open(config_file, "r", encoding="utf-8") as file:
        return json.load(file)


def convert_time(log_time):
    year = datetime.now().year
    return datetime.strptime(str(year) + " " + log_time, "%Y %b %d %H:%M:%S")


def read_log_file(log_file):
    events = []

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            failed = failed_login_regex.search(line)
            success = success_login_regex.search(line)

            if failed:
                events.append(
                    {
                        "time": convert_time(failed.group("time")),
                        "type": "failed",
                        "ip": failed.group("ip"),
                        "user": failed.group("user"),
                        "invalid_user": failed.group("invalid") is not None,
                        "raw": line,
                    }
                )

            elif success:
                events.append(
                    {
                        "time": convert_time(success.group("time")),
                        "type": "success",
                        "ip": success.group("ip"),
                        "user": success.group("user"),
                        "invalid_user": False,
                        "raw": line,
                    }
                )

    events.sort(key=lambda item: item["time"])
    return events


def check_bruteforce(events, rules):
    alerts = []
    failed_by_ip = defaultdict(list)
    limit = int(rules["failed_login_threshold"])
    window = timedelta(minutes=int(rules["time_window_minutes"]))

    for event in events:
        if event["type"] == "failed":
            failed_by_ip[event["ip"]].append(event)

    for ip, failures in failed_by_ip.items():
        for i in range(len(failures)):
            start_time = failures[i]["time"]
            matched = []

            for item in failures[i:]:
                if item["time"] - start_time <= window:
                    matched.append(item)

            if len(matched) >= limit:
                alerts.append(
                    {
                        "alert_type": "SSH_BRUTE_FORCE",
                        "severity": "HIGH",
                        "ip": ip,
                        "description": f"{len(matched)} failed login attempts in the time window",
                        "evidence_count": len(matched),
                        "first_seen": matched[0]["time"].isoformat(),
                        "last_seen": matched[-1]["time"].isoformat(),
                    }
                )
                break

    return alerts


def check_success_after_failures(events):
    alerts = []
    failed_by_ip = defaultdict(list)

    for event in events:
        if event["type"] == "failed":
            failed_by_ip[event["ip"]].append(event)

        if event["type"] == "success" and failed_by_ip[event["ip"]]:
            old_failures = failed_by_ip[event["ip"]]
            alerts.append(
                {
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "severity": "CRITICAL",
                    "ip": event["ip"],
                    "description": (
                        "successful login for "
                        + event["user"]
                        + " after "
                        + str(len(old_failures))
                        + " failed attempts"
                    ),
                    "evidence_count": len(old_failures) + 1,
                    "first_seen": old_failures[0]["time"].isoformat(),
                    "last_seen": event["time"].isoformat(),
                }
            )

    return alerts


def check_invalid_users(events, rules):
    alerts = []
    invalid_by_ip = defaultdict(list)
    limit = int(rules["invalid_user_threshold"])

    for event in events:
        if event["invalid_user"]:
            invalid_by_ip[event["ip"]].append(event)

    for ip, attempts in invalid_by_ip.items():
        if len(attempts) >= limit:
            alerts.append(
                {
                    "alert_type": "INVALID_USER_ATTEMPTS",
                    "severity": "MEDIUM",
                    "ip": ip,
                    "description": str(len(attempts)) + " invalid usernames tried",
                    "evidence_count": len(attempts),
                    "first_seen": attempts[0]["time"].isoformat(),
                    "last_seen": attempts[-1]["time"].isoformat(),
                }
            )

    return alerts


def save_reports(events, alerts, output_folder):
    output_folder.mkdir(parents=True, exist_ok=True)

    json_file = output_folder / "alerts.json"
    summary_file = output_folder / "summary.txt"

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)

    with open(summary_file, "w", encoding="utf-8") as file:
        file.write("SSH Log Alert Summary\n")
        file.write("=====================\n\n")
        file.write("Parsed log events: " + str(len(events)) + "\n")
        file.write("Alerts found: " + str(len(alerts)) + "\n\n")

        if len(alerts) == 0:
            file.write("No suspicious SSH activity was found.\n")
            return

        for alert in alerts:
            file.write("[" + alert["severity"] + "] " + alert["alert_type"] + "\n")
            file.write("IP: " + alert["ip"] + "\n")
            file.write("Details: " + alert["description"] + "\n")
            file.write("Evidence count: " + str(alert["evidence_count"]) + "\n")
            file.write("First seen: " + alert["first_seen"] + "\n")
            file.write("Last seen: " + alert["last_seen"] + "\n\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    rules = read_rules(args.config)
    events = read_log_file(args.log_file)

    alerts = []
    alerts += check_bruteforce(events, rules)
    alerts += check_success_after_failures(events)
    alerts += check_invalid_users(events, rules)

    project_folder = Path(__file__).resolve().parents[1]
    output_folder = project_folder / rules.get("output_directory", "reports")
    save_reports(events, alerts, output_folder)

    print("Parsed log events:", len(events))
    print("Alerts found:", len(alerts))
    print("Reports saved in:", output_folder)


if __name__ == "__main__":
    main()
