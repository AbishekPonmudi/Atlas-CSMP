import csv
from datetime import datetime
import main

def export_csv(results, filename=None):
    if not results:
        print(f"{main.YELLOW}[!] No scan results to export{main.RESET}")
        return

    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"havox_scan_results_{timestamp}.csv"

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
