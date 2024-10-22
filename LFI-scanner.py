import requests
import re
from concurrent.futures import ThreadPoolExecutor

OUTPUT_FILE = "found.txt"


def validate_file(filename):
    """
    Validates that the specified file exists and is not empty.
    """
    try:
        with open(filename, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                print(f"Error: File '{filename}' is empty.")
                return False
            else:
                return True
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return False


def check_lfi_vulnerability(url, directory):
    """
    Check if a given URL and directory combination is vulnerable to LFI attacks.
    """
    try:
        response = requests.get(url + directory)
        if response.status_code == 200:
            content = response.text
            if re.search(r"root:x:0:0", content) or re.search(r"etc/passwd", content):
                with open(OUTPUT_FILE, "a") as file:
                    file.write(f"{url + directory}\n")
                return f"Possible LFI vulnerability found: {url + directory}"
            else:
                return f"{url + directory} is not vulnerable to LFI attacks."
        else:
            return f"{url + directory} does not exist or is not reachable."
    except requests.exceptions.RequestException as e:
        return f"An exception occurred: {e}"


def scan_for_lfi_vulnerabilities(url, wordlist_file):
    """
    Scan a given URL for LFI vulnerabilities using a provided wordlist file.
    """
    if not validate_file(wordlist_file):
        exit(1)
    
    with open(wordlist_file, "r", encoding="utf-8") as file:
        directories = [line.strip() for line in file if line.strip()]
        with ThreadPoolExecutor() as executor:
            results = [executor.submit(check_lfi_vulnerability, url, directory) for directory in directories]
            for result in results:
                print(result.result())


if __name__ == "__main__":
    url = input("> URL to scan: ")
    wordlist_file = input("> Wordlist file name: ")

    if not validate_file(wordlist_file):
        exit(1)

    scan_for_lfi_vulnerabilities(url, wordlist_file)

    print("LFI vulnerability scan complete.")
