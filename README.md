# BFOR519---Compromised-Server
# Overview 
The objective of our project was to analyse multiple Linux system logs to identify indicators of compromise on a potentially attacked server. Using LNAV for multi log correlation, we examined authentication behaviour, kernel errors, service activity, and HTTP requests across log files including auth.log, kern.log, daemon.log, and Apache logs.
Through targeted filtering, pattern detection, and cross log comparisons, we identified several red flags such as repeated SSH segmentation faults, abnormal service restarts, and suspicious web requests signals commonly associated with exploitation attempts or system tampering.
Our project demonstrated practical digital forensics and incident response skills by showing how real analysts detect suspicious activity, validate security concerns, and extract meaningful insights from raw system logs using open source tools.

# Project Relevance
While modern Linux systems generate huge volumes of logs, those logs are of little value until one knows what to make of them. Our project is relavent because it relates to bringing raw, unorganized log data into meaningful security insights something every cybersecurity professional should possess.
Through the examination of real system logs, this project helps develop practical skills such as recognizing suspicious patterns, associating events from different sources, and finding early signs of an attack. Tools such as LNAV is used in many real security operations centers; experience with these tools makes one more familiar with common industry workflows.
The investigation also underlines how misconfigurations, vulnerable services, or weak authentication settings are used by the attackers. Knowledge of such weaknesses reinforces the importance of system hardening and continuous monitoring to avoid similar compromises in the future.
Overall, the project emulates real-world work performed by SOC Analysts, Threat Hunters, DFIR Specialists, Red/Blue Teamers, and Cloud Security Engineers. This means skills learned here will directly apply to cybersecurity careers.

# Methodology
1. Environment Setup
Commands executed: <br>
•sudo apt update — Updates package list <br>
•sudo apt install lnav -y — Installs lnav <br>
•lnav --version — Confirms installation <br>


3. Tools Used <br>
•	Ubuntu / WSL for running commands <br>
•	lnav for log navigation and filtering <br>
•	sanitized_log directory containing raw log files <br>

4. Opening Logs in lnav <br>
•	lnav /mnt/d/sanitized_log/ <br>
•	lnav automatically loads all supported log formats. <br>

5. Filters Applied (lnav) <br>
Inside lnav, the following filters were used:<br>
•	filter-in sshd.*segfault — Shows SSH segmentation faults <br>
•	filter-in accepted password — Shows successful SSH logins <br>
•	filter-in su:.*root — Shows privilege escalation attempts via su. <br>
•	filter-in php — Shows PHP-related log events <br>
•	filter-in invalid user — Highlights brute-force or unauthorized login attempts. <br>

# Screenshots & Evidence
# 1) sshd segfault <br>
Filter used : - :filter-in sshd.*segfault

# Evidence: <br>
Dozens of segfaults in sshd at the same memory address (RIP 8048e33), all within seconds, pointing to exploit attempts or binary corruption. <br>
The clustering of crashes across multiple PIDs shows instability triggered by repeated malicious inputs, not random system errors. <br>


![Alt text](Analysis/Screenshots/sshd_segfaults.jpg)











# 2) accepted password <br>
Filter used : - :filter-in accepted password <br>
 
# Evidence: 
Multiple entries show “Accepted password for dhg” from IP 190.166.87.164 across different times, proving repeated external access. <br>
Direct root logins from IPs like 151.81.204.141 and 122.226.202.12, confirming attackers had full administrative control. <br>


![Alt text](Analysis/Screenshots/Accepted_Password.jpg)











# 3) su.*root <br>
Filter used : - filter-in su:.*root <br>
 

# Evidence: 
Multiple entries show “session opened for user root” by user1 and user3, confirming privilege escalation from non-root accounts. <br>
Authentication failures followed by successful su attempts highlight weak or shared root credentials being abused. <br>


![Alt text](Analysis/Screenshots/Su_root.jpg)












# 4) php <br>
Filter used:- filter-in php <br>
 
# Evidence: 
Suspicious GET requests to wantsfly.com/prx2.php with hash parameters, indicating possible malicious probing or beaconing. <br>
WordPress activity (wp-cron.php, plugin scripts) alongside repeated 404s suggests attackers were testing vulnerable endpoints in the PHP stack. <br>


![Alt text](Analysis/Screenshots/PHP.jpg)












# 5) invalid user  <br>
Filter used:- filter-in Invalid user  <br>
 

# Evidence: 
Rapid sequence of “Invalid user” attempts from IP 65.208.122.48, cycling through usernames (diana, cam, astro, etc.) every few seconds. <br>
Each failed password attempt is paired with a port number, showing an automated tool systematically probing the server. <br>


![Alt text](Analysis/Screenshots/Brute Force.jpg)











# Indicators of Compromise (IOCs)
1.	Compromised Accounts <br>
•	root – multiple successful logins from external Ips <br>
•	dhg – repeated successful logins from 190.166.87.164 and 190.167.74.184 <br>
•	user1 – successful logins from 65.88.2.5 and 208.80.69.70 <br>
•	 fido – successful login from 94.52.185.9 <br>
•	user3 – suspicious su activity to root <br>

2.	 Malicious IP Addresses <br>
•	Successful SSH Logins <br>
o	190.166.87.164 <br>
o	190.167.74.184 <br>
o	151.81.204.141 <br>
o	151.81.205.100 <br>
o	122.226.202.12 <br>
o	88.214.26.70 <br>
o	61.168.227.12 <br>
o	94.52.185.9 <br>
o	188.131.23.37 <br>
o	65.88.2.5 <br>
o	208.80.69.70 <br>

3.	Brute-force Source <br>
•	65.208.122.48 (invalid user flood, rapid attempts across dozens of usernames). <br>

4.	System Instability <br>
•	Repeated sshd segfaults at memory address: <br>
•	RIP: 8048e33 <br>
•	Error code: 4 <br>
•	Pattern: Dozens of crashes in bursts, across multiple PIDs. <br>
5.	Web Layer Indicators <br>
•	Suspicious external requests to: <br>
•	wantsfly.com/prx2.php (with hash parameters) <br>
•	WordPress activity: <br>
•	wp-cron.php <br>
•	Plugin paths (e.g., google-syntax-highlighter) <br>
•	Frequent 404 probes against /img/original/... paths. <br>

6.	Behavioral Indicators <br>
•	Persistence: Repeated successful logins over multiple days from rotating IPs. <br>
•	Privilege Escalation: Frequent su attempts to root by user1 and user3. <br>
•	Brute-force: Automated spray attempts every 2 seconds from 65.208.122.48. <br>

# Key Findings 
1.	Direct Root Compromise <br>
•	Multiple successful SSH logins to the root account from external IPs. <br>
•	This confirms full system compromise with attackers gaining unrestricted control. <br>

2.	Multiple Account Breaches <br>
•	Accounts dhg, user1, and fido also show successful logins from suspicious IPs. <br>
•	Indicates broad credential exposure and attacker persistence across different user levels. <br>

3.	Brute-force Attack Evidence <br>
•	Source IP 65.208.122.48 launched rapid, automated login attempts against dozens of usernames. <br>
•	Confirms the server was exposed to internet-wide scanning and password-spray campaigns. <br>
4.	Privilege Escalation via su <br>
•	Frequent su attempts to root by user1 and user3, with failures followed by successes. <br> 
•	Suggests lateral movement and exploitation of shared or weak root credentials. <br>
5.	System Instability (sshd segfaults) <br>
•	Kernel logs show repeated sshd segmentation faults at the same memory address. <br>
•	Strongly suggests exploit attempts or binary tampering, undermining system integrity. <br>

6.	Web Layer Exposure <br>
•	WordPress cron jobs and plugin activity observed. <br>
•	Suspicious external requests (e.g., wantsfly.com/prx2.php) and repeated 404 probes. <br>
•	Indicates attackers may have targeted or exploited the WordPress/PHP stack. <br>
7.	Persistence Across Days <br>
•	Successful logins and activity spread over multiple days. <br>
•	Attackers maintained ongoing access, not just a one-time intrusion. <br>

8.	Impact Assessment <br>
•	Confidentiality: All data exposed due to root access. <br>
•	Integrity: System binaries and configs likely tampered with. <br>
•	Availability: sshd crashes caused instability. <br>






# Recommendation
1.	Immediate Isolation <br> 
•	Disconnect the server from the network to prevent further attacker activity. <br>
•	Disable all external SSH access immediately. <br>
2.	Full System Reinstallation (Mandatory) <br>
•	Due to confirmed root compromise, sshd crashes, and potential binary tampering, the operating system cannot be trusted. <br>
•	Perform a full OS reinstall on clean media. <br>
•	Do not reuse existing binaries, libraries, or configurations. <br>
3.	Credential Reset <br>
•	Reset all passwords for: <br> 
o	System users <br>
o	Admin accounts <br>
o	WordPress / PHP application users <br>
o	Database accounts <br>
•	Ensure passwords meet strong complexity requirements. <br>
•	Rotate SSH keys and revoke compromised ones. <br>
4.	Rebuild SSH and Authentication Security <br>
•	Disable password authentication; use SSH keys only. <br>
•	Configure fail2ban or equivalent intrusion-prevention tools. <br>
•	Restrict SSH access to specific IP addresses if possible. <br>
5.	Harden Web Stack (WordPress/PHP) <br>
•	Reinstall WordPress and all plugins from trusted sources. <br>
•	Remove unused plugins and themes. <br>
•	Rotate database credentials. <br>
•	Review WP-Cron and plugin activity logs for backdoors. <br>
6.	Log and Forensic Review (Post-Rebuild) <br>
•	Compare all identified malicious IPs against new logs. <br>
•	Enable centralized logging and monitoring. <br>
•	Implement regular integrity checks (e.g., AIDE). <br>
7.	Network Security Improvements <br>
•	Place server behind a firewall. <br>
•	Limit exposed services only expose what is absolutely necessary. <br>
•	Add rate-limiting and geo-blocking where appropriate. <br>
8.	Long-Term Recommendations <br>
•	Enforce regular updates and patching.  <br>
•	Enable 2FA for admin interfaces.  <br>
•	Perform periodic security audits. <br>





# Conclusion
The investigation shows that the server was not secure and was accessed by outsiders in ways that should never have been possible. There are clear signs of repeated logins, suspicious activity from different places, and unusual behavior that points to the system being under someone else’s control. 
The activity wasn’t just a one time event it continued over several days, showing that whoever got in was able to stay connected and move around freely. Alongside this, there were signs of instability and probing of the server’s applications, which suggests the compromise went beyond simple password guessing. 
In short, the system was fully taken over. The safest path forward is to rebuild it from scratch, change all access credentials, and put stronger protections in place so this kind of incident cannot happen again.



