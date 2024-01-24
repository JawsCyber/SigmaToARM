import requests
import json
import os
import pathlib
import logging
import yaml
import time
import re

"""
The processMultiResponse() function was written to handle cases where Uncoder returns multiple Sentinel rules.
From a look at them, it was highly rare that it would generate different rules at their core.
This function will take the first rule Uncoder supplies, and output it into the ARM template.
It's written so, in the event that you want all of the rules, you can easily modify the function to output multiple rules. 
"""

def processMultiResponse(response, root, file, input_dir, output_dir):
    responses = response.split('\n\n// ')
    seen_rules = set()
    for resp in responses[1:]:
        split_index = resp.rfind('\n')
        dataSource = resp[:split_index].strip()
        jsonResponse = resp[split_index:].strip()
        if jsonResponse and jsonResponse.startswith('{'):
            try:
                jsonResponse = json.loads(jsonResponse)
            except json.JSONDecodeError:
                logging.error(f"Error: Translation is not a valid JSON string for file {file}")
                logging.error(f"Invalid JSON string: {jsonResponse}")
                raise

            jsonResponseStr = json.dumps(jsonResponse, sort_keys=True)

            if jsonResponseStr in seen_rules:
                continue

            seen_rules.add(jsonResponseStr)

            relative_path = os.path.relpath(root, input_dir)
            if 'union *' in jsonResponse.get('query', '').lower():
                # SigmaNeedsReview speaks to rules generated with innefficient usage of "union *", as it is unable to determine the correct table (or isn't designed to be outputted into a Sentinel rule by default). 
                outputDir = os.path.join(output_dir, "SigmaNeedsReview", relative_path)
            else:
                outputDir = os.path.join(output_dir, "SigmaConverted", relative_path)

            pathlib.Path(outputDir).mkdir(parents=True, exist_ok=True)

            with open(os.path.join(outputDir, f"{file.rsplit('.', 1)[0]}--{dataSource}.json"), 'w') as f:
                f.write(json.dumps(jsonResponse, indent=4))

def processFile(root, file, input_dir, output_dir, url, headers):
    logging.info(f"Processing file: {file}")
    with open(os.path.join(root, file), 'r') as f:
        file_content = f.read()
        payload = {
            "text": file_content,
            "source_siem": "sigma",
            "target_siem": "sentinel-kql-rule"
        }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    if response.status_code != 200:
        logging.error(f"Error: Received status code {response.status_code} for file {file}")
        return
    # Sleep in an attempt to not overload the Uncoder docker instance. Feel free to play with the timings!
    time.sleep(0.1)
    response_json = response.json()
    if isinstance(response_json, dict):
        translation = response_json.get('translation')
    else:
        logging.error(f"Error: Response is not a dictionary for file {file}")
        return

    if translation and translation.startswith('//'):
        processMultiResponse(translation, root, file, input_dir, output_dir)
    else:
        if isinstance(response_json, dict):
            translation = response_json.get('translation')
        else:
            logging.error(f"Error: Response is not a dictionary for file {file}")
            return

        if translation is None:
            logging.error(f"Error: No translation received for file {file}")
        else:
            try:
                translation_json = json.loads(translation)
            except json.JSONDecodeError:
                logging.error(f"Error: Translation is not a valid JSON string for file {file}")
                logging.error(f"Invalid JSON string: {translation}")
                raise

            yaml_content = yaml.safe_load(file_content)
            analytic_id = yaml_content.get('id')
            # Can likely reference this template outside of the script, but for now its inline.
            arm_template = {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {
                    "workspace": {
                        "type": "String"
                    },
                    "analytic-id": {
                        "type": "string",
                        "defaultValue": analytic_id,
                        "minLength": 1,
                        "metadata": {
                            "description": "Unique id for the scheduled alert rule"
                        }
                    }
                },
                "resources": [
                    {
                        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                        "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',parameters('analytic-id'))]",
                        "apiVersion": "2020-01-01",
                        "kind": "Scheduled",
                        "location": "[resourceGroup().location]",
                        "properties": translation_json
                    }
                ]
            }

            relative_path = os.path.relpath(root, input_dir)
            if isinstance(translation_json, dict) and 'union *' in translation_json.get('query', '').lower():
                output_dir_path = os.path.join(output_dir, "SigmaNeedsReview", relative_path)
            else:
                output_dir_path = os.path.join(output_dir, "SigmaConverted", relative_path)

            pathlib.Path(output_dir_path).mkdir(parents=True, exist_ok=True)

            with open(os.path.join(output_dir_path, file.rsplit('.', 1)[0] + '.json'), 'w') as f:
                f.write(json.dumps(arm_template, indent=4))

def parseTagsFromDeTTECT(mapping):
    try:
        with open(mapping, 'r') as file:
            data = json.load(file)
        attackTechniqueIDs = [technique['techniqueID'] for technique in data.get('techniques', [])]
        return attackTechniqueIDs

    except Exception as exc:
        print(f"Error reading or parsing JSON file: {exc}")
        return []

def parseTagsFromSigma(sigma_rule):
    try:
        rule = yaml.safe_load(sigma_rule)
        tags = rule.get('tags', [])
        pattern = re.compile(r'^attack\.t\d{4}(?:\.\d{3})?$')
        attackTechniqueIDs = ['.'.join(tag.split('.')[1:]) for tag in tags if pattern.match(tag)]
        return attackTechniqueIDs

    except yaml.YAMLError as exc:
        print(f"Error parsing YAML: {exc}")
        return []

def findMappedSigmaRules(mappingFile, sigmaDir):
    attackTechniqueIDs = [tid.lower() for tid in parseTagsFromDeTTECT(mappingFile)]
    matchedSigmaRules = {}

    for root, dirs, files in os.walk(sigmaDir):
        for file in files:
            if file.endswith(".yml"):
                filePath = os.path.join(root, file)
                try:
                    with open(filePath, 'r') as sigmaFile:
                        sigmaRuleContent = sigmaFile.read()
                        sigmaTags = parseTagsFromSigma(sigmaRuleContent)

                        for tag in [t.lower() for t in sigmaTags]:
                            if tag in attackTechniqueIDs:
                                matchedSigmaRules[file] = filePath
                                break

                except Exception as e:
                    print(f"Error reading or parsing Sigma rule file '{filePath}': {e}")

    return matchedSigmaRules

def printDeTTECTMatches(dettect_file):
    try:
        with open(dettect_file, 'r') as file:
            data = json.load(file)
        attackTechniqueIDs = [technique['techniqueID'] for technique in data.get('techniques', [])]

        if not attackTechniqueIDs:
            print("No MITRE ATT&CK IDs found in the DeTTECT file.")
            return

        print("MITRE ATT&CK IDs found in DeTTECT file:")
        for tid in attackTechniqueIDs:
            print(tid)

    except Exception as exc:
        print(f"Error reading or parsing JSON file: {exc}")

def convertSigmaRules(input_dir, output_dir, url, headers, dettectFile=None):
    if dettectFile:
        matched_rules = findMappedSigmaRules(dettectFile, input_dir)
        filesToProcess = set(matched_rules.values())
    else:
        filesToProcess = {os.path.join(root, file) for root, _, files in os.walk(input_dir) for file in files if file.endswith(".yml")}

    for filePath in filesToProcess:
        processFile(os.path.dirname(filePath), os.path.basename(filePath), input_dir, output_dir, url, headers)
