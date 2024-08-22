#!/usr/bin/python

import sys
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages') 
import requests
import json
import time
import random
from datetime import datetime, timezone, timedelta
import logging 
import urllib3 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

## Configurable Settings ##

# Authentication
username = 'firemon' ## Must be firemon user (maybe DC system user would work)
password = 'firemon'
IP = 'localhost'    
device_group_id = '1' 

# Historical Usage 
populate_past_days = True  
num_past_days = 30  

# Logging
logging_level = logging.DEBUG  
enable_logging = False 

## Stop Editing Settings ##

auth_url = f'https://{IP}/securitymanager/api/authentication/login'
auth_payload = {
   'username': username,
   'password': password
}

session = requests.Session()  
auth_response = session.post(auth_url, json=auth_payload, verify=False) 

if auth_response.status_code == 200:
   auth_data = auth_response.json()
   auth_token = auth_data.get('token', '')
   session.headers.update({'X-FM-AUTH-TOKEN': auth_token})  
else:
   print("Authentication failed!")
   exit(1) 

# Base API URLs
devices_url = f'https://{IP}/securitymanager/api/domain/1/devicegroup/{{device_group_id}}/device'  
security_rules_url = f'https://{IP}/securitymanager/api/siql/secrule/stream?q=device%7Bid%3D{{device_id}}%7D'
collector_url = f'https://{IP}/securitymanager/api/collector/usage'  

if enable_logging:
  logging.basicConfig(filename='firemon_api_script.log', level=logging_level,  
            format='%(asctime)s - %(levelname)s - %(message)s')

# Function to fetch devices 
def get_devices(device_group_id):
    page = 0
    page_size = 100
    devices = []
    while True:
        devices_response = session.get(devices_url.format(device_group_id=device_group_id) + f"?page={page}&pageSize={page_size}", verify=False)
        if devices_response.status_code == 200:
            results = devices_response.json().get('results', [])
            if not results:  # No more results, break the loop
                break
            devices.extend(results)
            page += 1
        else:
            print(f"Error fetching devices on page {page}: {devices_response.text}")
            break
    return devices 

# Function to fetch security rules
def get_security_rules(device_id):
  rules_response = session.get(security_rules_url.format(device_id=device_id), headers={'Accept': 'application/json'}, verify=False)
  if rules_response.status_code == 200:
    return rules_response.json()
  else:
    print(f"Error fetching rules for device {device_id}: {rules_response.text}")
    return None

# Function to post usage data
def post_usage_data(device_id, rule, hit_count, skip_usage=False, timestamp=None):
  if timestamp is None:
      timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z') 
  usage_data = {
    "endDate": timestamp,
    "ruleUsages": [
      {
        "deviceId": device_id,
        "ruleId": rule['matchId'],
        "hitCount": hit_count if not skip_usage else 0,
        "sources": [{
          "id": source['matchId'],
          "parentId": source['matchId'],
          "hitCount": hit_count if not skip_usage else 0
        } for source in rule['sources']],
        "destinations": [{
          "id": destination['matchId'],
          "parentId": destination['matchId'],
          "hitCount": hit_count if not skip_usage else 0
        } for destination in rule['destinations']],
        "services": [{
          "id": service['matchId'],
          "parentId": service['matchId'],
          "hitCount": hit_count if not skip_usage else 0
        } for service in rule['services']],
        "apps": [{
          "id": app['matchId'],
          "parentId": app['matchId'],
          "hitCount": hit_count if not skip_usage else 0
        } for app in rule['apps']],
        "users": [{
          "id": user['matchId'],
          "parentId": user['matchId'],
          "hitCount": hit_count if not skip_usage else 0
        } for user in rule['users']]
      }
    ]
  }
  response = session.post(collector_url, headers={'Content-Type': 'application/json'}, data=json.dumps(usage_data), verify=False)
  if response.status_code in [200, 204]: 
    print(f"Usage data posted for rule {rule['matchId']}")
  else:
    print(f"Error posting usage data: {response.text}")

# Main execution loop
def main():
  devices = get_devices(device_group_id) 
  for device in devices:
    device_id = device['id']
    rules = get_security_rules(device_id)
    if rules:
      for i, rule in enumerate(rules): 
        if populate_past_days:
          for days_ago in range(num_past_days):
            past_date = datetime.now(timezone.utc) - timedelta(days=days_ago)
            past_datetime_str = past_date.strftime('%Y-%m-%dT%H:%M:%S%z')
            skip_usage = (i + 1) % 5 == 0 
            post_usage_data(device_id, rule, random.randint(10, 50), skip_usage, past_datetime_str) 
        else: 
          new_hit_count = random.randint(10, 50)
          skip_usage = (i + 1) % 5 == 0  
          post_usage_data(device_id, rule, new_hit_count, skip_usage) 
        time.sleep(1) 

if __name__ == "__main__":
  main()
