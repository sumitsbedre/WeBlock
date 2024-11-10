import subprocess

def run_nmap(ip_address, scan_type):
    scan_commands = {
        1: ["nmap", "-T4", "-A", "-v", ip_address],
        2: ["nmap", "-sS", "-sU", "-T4", "-A", "-v", ip_address],
        3: ["nmap", "-p", "1-65535", "-T4", "-A", "-v", ip_address],
        4: ["nmap", "-T4", "-A", "-v", "-Pn", ip_address],
        5: ["nmap", "-sn", ip_address],
        6: ["nmap", "-T4", "-F", ip_address],
        7: ["nmap", "-sV", "-T4", "-O", "-F", "--version-light", ip_address],
        8: ["nmap", "-sn", "--traceroute", ip_address],
    }
    
    if scan_type in scan_commands:
        try:
            # Run the selected Nmap command
            result = subprocess.run(scan_commands[scan_type], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("Nmap scan results:")
                print(result.stdout)  # Display scan results
            else:
                print("Nmap scan failed.")
                print(result.stderr)  # Display error message if scan failed
                
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("Invalid scan type selected.")

def main():
    print("Select the Nmap scan type:")
    print("1) Intense scan")
    print("2) Intense scan plus UDP")
    print("3) Intense scan, all TCP ports")
    print("4) Intense scan, no ping")
    print("5) Ping scan")
    print("6) Quick scan")
    print("7) Quick scan plus")
    print("8) Quick traceroute")
    
    try:
        scan_type = int(input("Enter the number corresponding to your choice: "))
        ip_address = input("Enter the IP address to scan: ")
        
        run_nmap(ip_address, scan_type)
        
    except ValueError:
        print("Invalid input. Please enter a number for the scan type.")

if __name__ == "__main__":
    main()
