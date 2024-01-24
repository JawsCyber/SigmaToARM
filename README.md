# SigmaToARM

## Summary

This project provides a method for converting the SigmaProject ruleset into Azure Resource Manager (ARM) templates specifically designed for use with Microsoft Sentinel Repositories. By automating this conversion process, the tool facilitates the integration of Sigma rules into Microsoft Sentinel, supporting DevOps and Sentinel-as-Code practices by creating a deployable rulebase. The library is easily modifyable to support Roota as well.

In version 1.1.0, I have introduced the ability to take a [DeTTECT project](https://github.com/rabobank-cdc/DeTTECT) mapping JSON, and only convert the appropriate Sigma rules that match the [Mitre Technique/Sub-Techniques](https://attack.mitre.org/techniques/enterprise/) relevant to your organisation.

## Purpose

I am a huge fan of the Sigma project for detection engineering, but when it comes to integrating these rules with codified deployments of Microsoft Sentinel it can be challenging due to format differences. I made this tool in an attempt to bridge the gap by converting the Sigma rules "en masse" to ARM templates, which are readily deployable via Microsoft Sentinel repositories. It simplifies the process, reduces manual effort, and helps maintain consistency in rule management.

## Prerequisites
- Tolerance to read/interpret spaghetti code if required.
- [UncoderIO](https://github.com/UncoderIO/Uncoder_IO)
- Python3 & Pip
- [Sigma Project Repository](https://github.com/SigmaHQ/sigma)
- Microsoft Sentinel
- [Microsoft Sentinel Repositories](https://learn.microsoft.com/en-us/azure/sentinel/ci-cd?tabs=azure-devops)

## Get Started
1. Clone the Repository
```
sudo apt update && sudo apt install git python3 python3-pip -y
git clone https://github.com/JawsCyber/SigmaToARM.git
cd SigmaToARM
```
2. Install Dependencies
```
pip3 install -r requirements.txt
```
3. Run the Script
```
python3 SigmaToARM.py -i "Path/To/Sigma/Rules/" -o "Desired/Output/Directory"
python3 SigmaToARM.py -i "Path/To/Sigma/Rules/" -o "Desired/Output/Directory" -d "DettectMappingJson.json"
```


**I'd also like to thank my main contributor to this project, GPT4.**