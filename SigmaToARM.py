import argparse
import logging
import time
import requests
import sys
from Imports import SigmaConverter

"""
Author: Ollie Legg (@JawsCyber, https://www.linkedin.com/in/OllieLegg/)
Version: 1.1.0
Contributors: Matt Felton (https://www.linkedin.com/in/matthew-felton-540206197/)
License: MIT License
"""

# Commandline Args
parser = argparse.ArgumentParser(description='Convert Sigma rules to Azure ARM templates.')
parser.add_argument('-i', '--input', required=True, help='Input directory containing Sigma rules.')
parser.add_argument('-o', '--output', required=True, help='Output directory for ARM templates.')
parser.add_argument('-d', '--dettect', required=False, help='Path to the DeTTECT mapping JSON.')
parser.add_argument('-dt', '--dettect-test', required=False, help='Path to the DeTTECT mapping JSON. Will only print matched techniques.')

args = parser.parse_args()

# Logging Config
logging.basicConfig(filename='SigmaToARM.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Uncoder URL/Headers
url = "http://localhost:8000/translate"
uiUrl = "http://localhost:4010/"
headers = {"Content-Type": "application/json"}

if __name__ == "__main__":
    try:
        logging.info("Script started")
        startTime = time.time()

        try:
            uncoderTest = requests.get(uiUrl, timeout=5)
            if uncoderTest.status_code == 200:
                logging.info("Uncoder service is running.")
            else:
                logging.error(f"Uncoder service returned status code {uncoderTest.statusCode}")
                sys.exit("Stopping script due to Uncoder service not running.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to connect to Uncoder service: {e}")
            sys.exit("Uncoder service not found, please ensure Uncoder is running before you run SigmaToARM.")


        if args.dettect_test:
            SigmaConverter.printDeTTECTMatches(args.dettect_test)
        else:
            SigmaConverter.convertSigmaRules(args.input, args.output, url, headers, args.dettect)

        end_time = time.time()
        logging.info(f"Script finished, total runtime: {end_time - startTime} seconds")

    except Exception as e:
        logging.error(f"An error occurred: {e}")