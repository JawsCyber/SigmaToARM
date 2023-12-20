import argparse
import logging
import time
import SigmaConverter

"""
Author: Ollie Legg (@JawsCyber)
Version: 1.0.0
License: MIT License
"""

# Commandline Args
parser = argparse.ArgumentParser(description='Convert Sigma rules to Azure ARM templates.')
parser.add_argument('-i', '--input', required=True, help='Input directory containing Sigma rules')
parser.add_argument('-o', '--output', required=True, help='Output directory for ARM templates')
args = parser.parse_args()

# Logging Config
logging.basicConfig(filename='SigmaToARM.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Uncoder URL/Headers
url = "http://localhost:8000/translate"
headers = {"Content-Type": "application/json"}

if __name__ == "__main__":
    try:
        logging.info("Script started")
        start_time = time.time()
        SigmaConverter.convertSigmaRules(args.input, args.output, url, headers)
        end_time = time.time()
        logging.info(f"Script finished, total runtime: {end_time - start_time} seconds")

    except Exception as e:
        logging.error(f"An error occurred: {e}")