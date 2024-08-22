# FireMonDemoTools
Scripts for use in FireMon demo environments.

## populateHits.py
The code simulates usage data for FireMon security rules and then transmits this simulated
data to the FireMon collector API. This is likely for testing or demo purposes within your
FireMon environment.

Usage: 
Edit settings below, set the device group to target, and if you want to populate historical usage. Will take a long time to run if doing several devices with historical usage.
If not doing historical usage the hits will appear at the time the script was ran.
When setting on a cronjob, pipe output to /dev/null to prevent system logs from filling up.

Example cron usage:                                                                       
0 8 * * * /usr/bin/python3.9 /path/to/populateHits.py > /dev/null 2>&1

To Do:
- Optimize API calls, maybe one API call to post usage instead of several.
- Human readable output (device names, rule names, object names etc).
- Make the random number thresholds a configurable value.
- Currently this skips every 5 rules (so there is some unused rules) make that a configurable  value.
