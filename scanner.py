import argparse
import hashlib
import requests
import os
import configparser

def get_hash(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def load_config():
    # Check .env file
    env_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if line.startswith('VT_API_KEY='):
                    return line.split('=', 1)[1].strip()
    
    # Check config file
    config = configparser.ConfigParser()
    config_path = os.path.expanduser("~/.vt_scanner_config")
    if os.path.exists(config_path):
        config.read(config_path)
        if 'DEFAULT' in config and 'api_key' in config['DEFAULT']:
            return config['DEFAULT']['api_key']
    return None

def scan_with_vt(hash_val, api_key):
    if not api_key:
        api_key = os.getenv('VT_API_KEY')
    if not api_key:
        api_key = load_config()
    if not api_key:
        print("Error: Provide API key via --api-key argument, set VT_API_KEY environment variable, create ~/.vt_scanner_config with [DEFAULT] api_key = your_key, or add VT_API_KEY=your_key to .env file")
        return
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        undetected = stats['undetected']
        harmless = stats['harmless']
        print(f"Malicious detections: {malicious}")
        print(f"Suspicious detections: {suspicious}")
        print(f"Undetected: {undetected}")
        print(f"Harmless: {harmless}")
        if malicious > 0:
            print("File is likely malicious")
        elif suspicious > 0:
            print("File is suspicious")
        else:
            print("File appears clean")
    elif response.status_code == 404:
        print("File not found in VirusTotal database. Consider uploading for a new scan.")
    else:
        print(f"Error querying VirusTotal: {response.status_code} - {response.text}")

def main():
    parser = argparse.ArgumentParser(description="Scan file for malware using VirusTotal API")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--api-key", help="VirusTotal API key (or set VT_API_KEY env var)")
    args = parser.parse_args()
    if not os.path.isfile(args.file):
        print("Error: File does not exist")
        return
    hash_val = get_hash(args.file)
    print(f"SHA256: {hash_val}")
    scan_with_vt(hash_val, args.api_key)

if __name__ == "__main__":
    main()