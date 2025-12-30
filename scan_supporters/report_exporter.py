import csv
from datetime import datetime
import main
import sys
from helper.iac_utils.iac_scan import OutputFormatter

def export_csv(results, filename=None):
    if not results:
        print(f"{main.YELLOW}[!] No scan results to export{main.RESET}")
        return

    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Atlas_Cloud_scan_results_{timestamp}.csv"

    fieldnames = [
        "Category",
        "Check",
        "Description",
        "Resource",
        "Status",
        "Remediation"
    ]

    try:
        with open(filename, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for row in results:
                writer.writerow({k: row.get(k, "") for k in fieldnames})

        print(f"{main.GREEN}[+] Scan results exported to {filename}{main.RESET}")

    except Exception as e:
        print(f"{main.RED}[!] Failed to export CSV: {e}{main.RESET}")

def export_txt(results, filename=None):

    if not results:
        print(f"{main.YELLOW}[!] No scan results to export{main.RESET}")
        return

    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Atlas_Iac_scan_results_{timestamp}.txt"

    try:
        with open(filename, "w", encoding="utf-8") as f:
            original_stdout = sys.stdout
            sys.stdout = f

            try:
                OutputFormatter.print_findings(
                    results["findings"],
                    results["stats"],
                )
            finally:
                sys.stdout = original_stdout

        print(f"{main.GREEN}[+] IaC scan results exported to {filename}{main.RESET}")

    except Exception as e:
        print(f"{main.RED}[!] Failed to export TXT: {e}{main.RESET}")
