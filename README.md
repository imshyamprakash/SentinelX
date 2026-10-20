# SentinelX

AI-Powered Cyber Threat Investigation Platform

## Goal

Build a professional cybersecurity platform from scratch while understanding every component.

## Detection rules

- Brute force: at least 3 failed logins from one IP; the time-aware rule also identifies 3 failures within 60 seconds.
- Port scan: at least 5 distinct ports targeted by one IP within 60 seconds.
- Multi-account credential attack: failed logins against at least 3 distinct usernames from one IP within 5 minutes. Repeated attempts against one username do not satisfy this rule.

Each detected port scan or multi-account attack adds 5 points to that IP's risk score. Multi-account log entries include the account, for example: `Failed login for user alice`.

## Author

Shyamprakash N
