# This piece of code is belongs to havox and this code is done without using Any generative models
# copyrights@havox

import argparse
import connector
import time
import os
import config.dbConfig as dbConfig
from helper.aws.S3 import s3_functions
from helper.aws.IAM import iam_functions
from helper.aws.EC2 import ec2_helper
from tabulate import tabulate 
import sys
import config
from config.get_resource import AWSResourceCounter
from datetime import datetime

# ANSI color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREY = "\033[90m"

def print_colored_status(status):
    if status == "PASS":
        return f"{GREEN}{status}{RESET}"
    elif status == "FAIL":
        return f"{RED}{status}{RESET}"
    elif status == "HIGH" or status == "WARN":
        return f"{YELLOW}{status}{RESET}"
    elif status == "INFO":
        return f"{CYAN}{status}{RESET}"
    elif status == "MUTED" or status == "ERROR":
        return f"{YELLOW}{status}{RESET}"
    return status

def clear_src():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system("clear")

def print_progress_bar(iteration, total, status_counts=None, service_name=None):
    try:
        iteration = float(str(iteration)) if iteration is not None else 0.0
        total = float(str(total)) if total is not None else 1.0
        if total <= 0:
            total = 1.0
        percent = min(100.0, round(100.0 * (iteration / total), 1))
        filled_length = int(50.0 * (iteration / total)) if total > 0 else 0
        bar = f"{GREEN}▰{RESET}" * filled_length + f"{GREY}▱{RESET}" * (50 - filled_length)
        service_label = f" [{service_name}]" if service_name else ""
        sys.stdout.write(f"\rProgress{service_label}: |{bar}| {percent}% Completed")
        sys.stdout.flush()

        if float(iteration) >= float(total) and iteration == total:
            print(f"\rProgress{service_label}: |{bar}| 100% Completed\n")
    except (ValueError, TypeError) as e:
        print(f"Error in print_progress_bar: {e}, iteration={iteration}, total={total}, types=(iteration: {type(iteration)}, total: {type(total)})")

def print_header():
    print("\n")
    print(f"{BLUE}  ██╗  ██╗ █████╗ ██╗   ██╗ ██████╗ ██╗  ██╗ {RESET}")
    print(f"{BLUE}  ██║  ██║██╔══██╗╚██╗ ██╔╝██╔═══██╗██║  ██║ {RESET}")
    print(f"{BLUE}  ███████║███████║ ╚████╔╝ ██║   ██║███████║ {RESET}")
    print(f"{BLUE}  ██╔══██║██╔══██║  ╚██╔╝  ██║   ██║██╔══██║ {RESET}")
    print(f"{BLUE}  ██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║ {RESET}")
    print(f"{BLUE}  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ {RESET}")
    print(f"{CYAN}                    === Havox CLoud scanner CLI Tool v1.0.1 === {RESET}")
    print(f"{CYAN}           The comprehensive cloud security assessment tool {RESET}")
    print(f"{CYAN}                     Copyright © 2025 Havox.vercel.com {RESET}")


def print_service_summary(service_name, results):
    if not results:
        print(f"{YELLOW}No {service_name} issues found.{RESET}")
        return
    headers = ["Category", "Check", "Description", "Resource", "Status", "Remediation"]
    data = [[r["Category"], r["Check"], r["Description"], r["Resource"], print_colored_status(r["Status"]), r["Remediation"]] for r in results]
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))

def print_overview_results(config, scan_results, status_counts_global=None):
    s3_results = [r for r in scan_results if r.get("Category") == "S3"]
    iam_results = [r for r in scan_results if r.get("Category") == "IAM"]
    ec2_results = [r for r in scan_results if r.get("Category") == "EC2"]

    def get_service_metrics(results, category):
        critical = sum(r.get("Critical", 0) for r in results)  
        high = sum(r.get("High", 0) for r in results)         
        medium = sum(r.get("Medium", 0) for r in results)   
        low = sum(r.get("Error", 0) for r in results)          
        muted = sum(r.get("Muted", 0) for r in results)    
        total = len(results)
        status = "fail" if any(r.get("Status") in ["FAIL", "ERROR"] for r in results) else "info (0)"
        return critical, high, medium, low, muted, status, total

    s3_critical, s3_high, s3_medium, s3_low, s3_muted, s3_status, s3_total = get_service_metrics(s3_results, "S3")
    iam_critical, iam_high, iam_medium, iam_low, iam_muted, iam_status, iam_total = get_service_metrics(iam_results, "IAM")
    ec2_critical, ec2_high, ec2_medium, ec2_low, ec2_muted, ec2_status, ec2_total = get_service_metrics(ec2_results, "EC2")

    start_time = datetime.now()
    print(f"\n{YELLOW}\n=== Scan Overview ({start_time.strftime('%Y-%m-%d %I:%M %p IST')}) ==={RESET}")
    headers = ["Provider", "Service", "Status", "Critical", "High", "Passed", "Low", "Muted"]
    data = [
        ["aws", "S3", print_colored_status(s3_status), 
         f"{RED}{s3_critical}{RESET}" if s3_critical > 0 else s3_critical, 
         f"{YELLOW}{s3_high}{RESET}" if s3_high > 0 else s3_high, 
         f"{GREEN}{s3_medium}{RESET}" if s3_medium > 0 else s3_medium, 
         f"{BLUE}{s3_low}{RESET}" if s3_low > 0 else s3_low, 
         f"{CYAN}{s3_muted}{RESET}" if s3_muted > 0 else s3_muted],
        ["aws", "IAM", print_colored_status(iam_status), 
         f"{RED}{iam_critical}{RESET}" if iam_critical > 0 else iam_critical, 
         f"{YELLOW}{iam_high}{RESET}" if iam_high > 0 else iam_high, 
         f"{GREEN}{iam_medium}{RESET}" if iam_medium > 0 else iam_medium, 
         f"{BLUE}{iam_low}{RESET}" if iam_low > 0 else iam_low, 
         f"{CYAN}{iam_muted}{RESET}" if iam_muted > 0 else iam_muted],
        ["aws", "EC2", print_colored_status(ec2_status), 
         f"{RED}{ec2_critical}{RESET}" if ec2_critical > 0 else ec2_critical, 
         f"{YELLOW}{ec2_high}{RESET}" if ec2_high > 0 else ec2_high, 
         f"{GREEN}{ec2_medium}{RESET}" if ec2_medium > 0 else ec2_medium, 
         f"{BLUE}{ec2_low}{RESET}" if ec2_low > 0 else ec2_low, 
         f"{CYAN}{ec2_muted}{RESET}" if ec2_muted > 0 else ec2_muted],
        ["aws", "CloudFormation", "INFO (Dev)..."], 
        ["aws", "lambda", "INFO (Dev)..."], 
        ["aws", "cloudWatch", "INFO (Dev)..."], 
        ["aws", "config", "INFO (Dev)..."], 
        ["aws", "cloudTrail", "INFO (Dev)..."], 
    ]
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))
    
    def calculate_percent(count, total):
        return f"{round((count / total * 100), 2)}% ({count})" if total > 0 else "0.00% (0)"
    
    total_checks = s3_total + iam_total + ec2_total
    failed = s3_critical + iam_critical + ec2_critical
    passed = s3_medium + iam_medium + ec2_medium
    warned = s3_high + iam_high + ec2_high
    info = s3_low + iam_low + ec2_low
    muted = s3_muted + iam_muted + ec2_muted
    
    print(f"\n{YELLOW}\n=== Detailed Scan Summary ({start_time.strftime('%Y-%m-%d %I:%M %p IST')}) ==={RESET}")
    headers = ["Status Breakdown", "Percentage (Count)", "Severity Breakdown", "Count"]
    data = [
        ["Failed", f"{RED}{calculate_percent(failed, total_checks)}{RESET}", "Critical", failed],
        ["Passed", f"{GREEN}{calculate_percent(passed, total_checks)}{RESET}", "Passed", passed],
        ["Warned", f"{YELLOW}{calculate_percent(warned, total_checks)}{RESET}", "High", warned],
        ["Info",   f"{BLUE}{calculate_percent(info, total_checks)}{RESET}", "Low", info],
        ["Muted", f"{CYAN}{calculate_percent(muted, total_checks)}{RESET}", "Muted", muted],
    ]
    
    low = warned + info
    low_percentage = round((low / total_checks  * 100),2) if total_checks > 0 else 0.0
   
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))   
    print(f"\n{YELLOW}=== CIS Benchmark Compliance Status ==={RESET}")
    compliance_data = [
        [f"{BLUE}Total Resource{RESET}",f"{BLUE}{actual_resource}{RESET}"],
        [f"{RED}Non-Compliance{RESET}",f"{RED}{calculate_percent(failed,total_checks)}{RESET}"],
        [f"{GREEN}Compliance{RESET}",  f"{GREEN}{calculate_percent(passed,total_checks)}{RESET}"],
        [f"{YELLOW}Low/Warning{RESET}",f"{YELLOW}{low_percentage}% ({low}){RESET}"],
    ]

    print(tabulate(compliance_data,headers=[],tablefmt="fancy_grid"))


    # print(f"\n{RED}=== Total Resources Checks {total_checks}...{  }\n")

    # print(account_id)
    print(f"\n{CYAN}Account ID: {account_id} | Region: {config.get('region', 'Unknown')} | "f"Duration: {datetime.now() - start_time}{RESET}")

# For cache 
scan_result_cache = []
status_count_cache = {"PASS": 0, "FAIL": 0, "HIGH": 0, "INFO": 0, "MUTED": 0, "ERROR": 0, "WARN": 0}


account_id = None

s1 = AWSResourceCounter()

def main():
    
    db_set = dbConfig.get_config_status()
    if db_set is False or db_set is None:
        print(f"{YELLOW}[*] Initializing configuration...{RESET}")
        cloud_config = connector.aws_config_creds()
        dbConfig.db_connection(cloud_config['access_key'], cloud_config['secret_key'], cloud_config['region'], True)
        print(f"{GREEN}[+] Configuration initialized successfully.{RESET}")
    elif db_set is True:
        print(f"{GREEN}[+] havox CSPM Tool started successfully.{RESET}")
    # time.sleep(1)

    AWSconfig = dbConfig.get_config()
    if not AWSconfig:
        print(f"{RED}[-] No configuration found. Please run 'aws config' to set up AWS credentials.{RESET}")
        return

    print(f"\n{CYAN}[*] Starting havox CSPM Assessment...{RESET}\n")
    
    total_checks = [0]  # Shared total checks across all services
    scan_results = []
    status_counts = {"PASS": 0, "FAIL": 0, "HIGH": 0, "INFO": 0, "MUTED": 0, "ERROR": 0, "WARN": 0}

    estimated_total = 600
    print_progress_bar(total_checks[0], estimated_total, status_counts)

    def update_progress(checks, counts):
        
        try:
            checks = int(float(str(checks))) if checks is not None else 0
            total_checks[0] += checks
            for status, count in counts.items():
                status_counts[status] = status_counts.get(status, 0) + int(float(str(count))) if count is not None else 0
            
            current_checks = total_checks[0]
            print_progress_bar(current_checks, estimated_total, status_counts)
            sys.stdout.flush() 
        except (ValueError, TypeError) as e:
            print(f"Process Bar issue {e}, checks={checks}, counts={counts}, total_checks={total_checks[0]}")
    
    global actual_resource
    total = s1.run_count()
    actual_resource = s1.print_totals(total)

    s3_functions.collect_and_check_bucket(AWSconfig, scan_results, update_progress)
    iam_functions.collect_and_check_iam(AWSconfig, scan_results, update_progress)
    ec2_helper.collect_and_check_ec2(AWSconfig, scan_results, update_progress)

    global account_id
    account_id = dbConfig.get_account_name()

    print_progress_bar(total_checks[0], estimated_total, status_counts)

    # Update cache
    global scan_result_cache
    global status_count_cache
    scan_result_cache = scan_results
    status_count_cache = status_counts

    time.sleep(1)  # Sync time

    print_overview_results(AWSconfig, scan_results, status_counts)

    print(f"\n{CYAN}[*] Starting havox CSPM Shell (Type 'help' for commands){RESET}")

    press_count = 1

    while True:
        try:
            command = input(f"{GREEN}[scyber@CSPM]$> {RESET}").strip().lower()
            if command:
                handle_command(command, AWSconfig)
                continue
        except KeyboardInterrupt:
            press_count += press_count
            print(f"\n{YELLOW}[*] Thinking''' you press CTRL + C Right, to sign-off use 'exit' or press CTRL + C again:){RESET}")
            if press_count > 3:
                break
            else:
                continue


service_map = {
    's3': 'S3',
    'iam': 'IAM',
    'ec2': 'EC2'
}

def handle_command(command, AWSconfig):
    command = command.lower()
    
    if command == 'aws config':
        print(f"{YELLOW}[*] Re-configuring AWS credentials...{RESET}")
        cloud_config = connector.aws_config_creds()
        dbConfig.db_connection(cloud_config['access_key'], cloud_config['secret_key'], cloud_config['region'], True)
        print(f"{GREEN}[+] Credentials updated successfully.{RESET}")

    elif command == 'status':
        print(f"{GREEN}[+] Fetching status...{RESET}")
        if dbConfig.status_verify():
            print(f"{GREEN}[+] CSPM is active and operational.{RESET}")
        else:
            print(f"{RED}[-] CSPM is inactive. Run 'aws config' to activate.{RESET}")

    elif command == 'cloud status':
        print_overview_results(AWSconfig, scan_result_cache, status_count_cache)
    
    elif command == 'restart' or command == 'reboot' or command == 'rescan':
        print(f"\n{GREY}Restart initiated...{RESET}\n")
        time.sleep(2)
        print(f"{RED}[*]{RESET}{GREEN}starting all service may take some time{RESET}\n")
        main()
    
    elif command == 'download result':
        print("Yet to implement...")

    elif command.startswith('scan'):
        if not AWSconfig:
            print(f"{RED}[-] Configuration missing. Run 'aws config' first.{RESET}")
            return
        if command == 'scan':
            print("Service info needed >> use help")
        
        if command.strip() == 'scan all':
            services = list(service_map.keys())
        else:
            raw = command.replace('scan', '').strip()
            services = [s.strip() for s in raw.split(',') if s.strip()]
        
        print(f"\n{YELLOW}Starting scan...{RESET}\n")
        scan_results = []
        total_checks = [0]
        status_counts = {"PASS": 0, "FAIL": 0, "HIGH": 0, "INFO": 0, "MUTED": 0, "ERROR": 0, "WARN": 0}
        estimated_total = 100 if 's3' in services else 100 if 'iam' in services else 100

        def update_progress(checks, counts):
            try:
                checks = int(float(str(checks))) if checks is not None else 0
                total_checks[0] += checks
                for status, count in counts.items():
                    status_counts[status] = status_counts.get(status, 0) + int(float(str(count))) if count is not None else 0

                
                current_checks = estimated_total
                current_checks = total_checks[0]
                # print_progress_bar(current_checks, estimated_total, status_counts, service_map.get(services[0]) if services else None)
                sys.stdout.flush() 
            except (ValueError, TypeError) as e:
                print(f"Error in update_progress: {e}, checks={checks}, counts={counts}, total_checks={total_checks[0]}")

        print_progress_bar(0, estimated_total, status_counts, service_map.get(services[0]) if services else None)
        sys.stdout.flush()

        for svc in services:
            if svc not in service_map:
                print(f"\n{RED}[!] Unknown service '{svc}'{RESET}")
                
            try:
                if svc == 's3':
                    s3_functions.collect_and_check_bucket(AWSconfig, scan_results, update_progress)
                elif svc == 'iam':
                    iam_functions.collect_and_check_iam(AWSconfig, scan_results, update_progress)
                elif svc == 'ec2':
                    ec2_helper.collect_and_check_ec2(AWSconfig, scan_results, update_progress)
                else:
                    print(f"{YELLOW}[*] Unable to find the service make sure you entered the correct service, or use help...{RESET}\n")
                    continue
            except KeyError as e:
                print(f"Error code: {e}")
                continue

        # Only print the final progress bar if there were checks
        if total_checks[0] > 0:
            print_progress_bar(total_checks[0], estimated_total, status_counts, service_map.get(services[0]) if services else None)
            print("")
        time.sleep(1) 
        for svc in services:
            if svc not in service_map:
                continue
            print_service_summary(service_map[svc], [r for r in scan_results if r.get("Category") == service_map[svc]])

    elif command in ['help', 'h']:
        print(f"""
{CYAN}=== havox CSPM Command's ===
{YELLOW}- aws config       : Re-configure AWS credentials
- scan s3          : Scan S3 buckets
- scan iam         : Scan IAM resources
- scan ec2         : Scan EC2 instances
- scan s3.....     : Scan multiple services e.g(scan iam, s3, ec2 ....)
- scan all         : Scan all supported services
- cloud status     : List the overall compliance status with checks with Frameworks
- status           : Check CSPM status
- reboot, restart  : initiate rescan manually
- exit / quit / !q : Exit the tool
- help             : Show this help message{RESET}
""")
    elif command in ['exit', 'quit', '!q']:
        print(f"{YELLOW}[*] Exiting havox CSPM Tool...{RESET}")
        exit(0)
    else:
        print(f"{RED}[!] Unknown command: '{command}'. Type 'help' for assistance.{RESET}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='havox CSPM Tool')
    parser.add_argument('--version', action='version', version='havox CSPM Tool v1.1')
    args = parser.parse_args()
    clear_src()
    print_header()
    main()