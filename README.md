# BFOR519---Compromised-Server
Overview 
The objective of our project was to analyse multiple Linux system logs to identify indicators of compromise on a potentially attacked server. Using LNAV for multi log correlation, we examined authentication behaviour, kernel errors, service activity, and HTTP requests across log files including auth.log, kern.log, daemon.log, and Apache logs.
Through targeted filtering, pattern detection, and cross log comparisons, we identified several red flags such as repeated SSH segmentation faults, abnormal service restarts, and suspicious web requests signals commonly associated with exploitation attempts or system tampering.
Our project demonstrated practical digital forensics and incident response skills by showing how real analysts detect suspicious activity, validate security concerns, and extract meaningful insights from raw system logs using open source tools.

Project Relevance
While modern Linux systems generate huge volumes of logs, those logs are of little value until one knows what to make of them. Our project is relavent because it relates to bringing raw, unorganized log data into meaningful security insights something every cybersecurity professional should possess.
Through the examination of real system logs, this project helps develop practical skills such as recognizing suspicious patterns, associating events from different sources, and finding early signs of an attack. Tools such as LNAV is used in many real security operations centers; experience with these tools makes one more familiar with common industry workflows.
The investigation also underlines how misconfigurations, vulnerable services, or weak authentication settings are used by the attackers. Knowledge of such weaknesses reinforces the importance of system hardening and continuous monitoring to avoid similar compromises in the future.
Overall, the project emulates real-world work performed by SOC Analysts, Threat Hunters, DFIR Specialists, Red/Blue Teamers, and Cloud Security Engineers. This means skills learned here will directly apply to cybersecurity careers.

Methodology
1. Environment Setup
Commands executed:
•	sudo apt update — Updates package list
•	sudo apt install lnav -y — Installs lnav
•	lnav --version — Confirms installation


2. Tools Used
•	Ubuntu / WSL for running commands
•	lnav for log navigation and filtering
•	sanitized_log directory containing raw log files

3. Opening Logs in lnav
•	lnav /mnt/d/sanitized_log/
•	lnav automatically loads all supported log formats.

4. Filters Applied (lnav)
Inside lnav, the following filters were used:
•	filter-in sshd.*segfault — Shows SSH segmentation faults
•	filter-in accepted password — Shows successful SSH logins
•	filter-in su:.*root — Shows privilege escalation attempts via su.
•	filter-in php — Shows PHP-related log events
•	filter-in invalid user — Highlights brute-force or unauthorized login attempts


