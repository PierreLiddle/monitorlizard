#/bin/bash
mkdir DbBackup >/dev/null 2>&1 
aws dynamodb scan --table-name SIEM > ./DbBackup/MonitorLizardDynamoDB.json
