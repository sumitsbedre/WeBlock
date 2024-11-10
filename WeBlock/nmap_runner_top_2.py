import subprocess

def run_nmap_scan(target, scan_type):
    if scan_type == '1':
        command = f"nmap -T4 -A -v {target}"  # Intense Scan
    elif scan_type == '2':
        command = f"nmap -sS -sU -T4 -A -v {target}"  # Intense Scan Plus UDP
    else:
        print("Invalid scan type selected.")
        return None

    try:
        # Execute the command and capture the output
        result = subprocess.check_output(command, shell=True, text=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error executing scan: {e}"

def main():
    print("Select the scan type:")
    print("1) Intense Scan (nmap -T4 -A -v)")
    print("2) Intense Scan Plus UDP (nmap -sS -sU -T4 -A -v)")

    scan_type = input("Enter the number for the desired scan: ")
    target = input("Enter the IP Address or Domain to scan: ")

    print(f"Running scan on {target}...")
    scan_result = run_nmap_scan(target, scan_type)

    if scan_result:
        print("\nScan Result:")
        print(scan_result)

if __name__ == '__main__':
    main()
