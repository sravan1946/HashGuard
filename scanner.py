import argparse
import hashlib
import requests
import os
import configparser
import time
from tqdm import tqdm
try:
    from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
    HAS_TOOLBELT = True
except ImportError:
    HAS_TOOLBELT = False

def humanize_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

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

def get_analysis_results(analysis_id, api_key):
    import time
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}
    with tqdm(total=100, desc="Analyzing", unit="%") as pbar:
        progress = 0
        while True:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    status = data['data']['attributes']['status']
                    if status == 'completed':
                        pbar.update(100 - progress)
                        pbar.close()
                        stats = data['data']['attributes']['stats']
                        malicious = stats['malicious']
                        suspicious = stats['suspicious']
                        undetected = stats['undetected']
                        harmless = stats['harmless']
                        print("Analysis completed:")
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
                        break
                    else:
                        pbar.set_description(f"Status: {status}")
                        if progress < 90:
                            pbar.update(10)
                            progress += 10
                        time.sleep(10)
                else:
                    pbar.close()
                    print(f"Error getting analysis: {response.status_code} - {response.text}")
                    break

def upload_file(file_path, api_key):
    file_size = os.path.getsize(file_path)
    if file_size > 32 * 1024 * 1024:  # 32MB limit for free VT API
        print(f"Error: File is too large ({humanize_size(file_size)}). VirusTotal free API limits uploads to 32MB.")
        return
    size_str = humanize_size(file_size)
    print(f"Uploading file ({size_str})...")
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    if HAS_TOOLBELT:
        with open(file_path, 'rb') as f:
            encoder = MultipartEncoder(fields={'file': ('file', f, 'application/octet-stream')})
            with tqdm(total=encoder.len, unit='B', unit_scale=True, desc='Uploading') as pbar:
                monitor = MultipartEncoderMonitor(encoder, lambda monitor: pbar.update(monitor.bytes_read - pbar.n))
                headers['Content-Type'] = monitor.content_type
                response = requests.post(url, data=monitor, headers=headers)
    else:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        data = response.json()
        analysis_id = data['data']['id']
        print(f"\nFile uploaded successfully. Analysis ID: {analysis_id}")
        print("Waiting for analysis to complete...")
        get_analysis_results(analysis_id, api_key)
    elif response.status_code == 413:
        print("Error: File is too large. VirusTotal free API limits file uploads to 32MB. Consider using a premium account or scanning the hash if the file is already known.")
    elif response.status_code == 429:
        print("Error: Rate limit exceeded. Too many requests. Try again later.")
    elif response.status_code == 401:
        print("Error: Invalid API key. Check your VirusTotal API key.")
    else:
        print(f"Error uploading file: {response.status_code} - {response.text}")

def scan_with_vt(hash_val, api_key, file_path, upload):
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
        print("File not found in VirusTotal database.")
        if upload:
            print("Uploading file for scan...")
            upload_file(file_path, api_key)
        else:
            print("Use --upload to upload the file for a new scan.")
    else:
        print(f"Error querying VirusTotal: {response.status_code} - {response.text}")

def main():
    parser = argparse.ArgumentParser(description="Scan file for malware using VirusTotal API")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--api-key", help="VirusTotal API key (or set VT_API_KEY env var)")
    parser.add_argument("--upload", action="store_true", help="Upload file if not found in database")
    args = parser.parse_args()
    if not os.path.isfile(args.file):
        print("Error: File does not exist")
        return
    hash_val = get_hash(args.file)
    print(f"SHA256: {hash_val}")
    scan_with_vt(hash_val, args.api_key, args.file, args.upload)

if __name__ == "__main__":
    main()
