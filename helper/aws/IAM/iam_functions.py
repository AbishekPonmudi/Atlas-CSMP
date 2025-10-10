from collector.aws.IAM.get_iam_policy import get_iam_details
from plugins.aws.IAM.iam_all_check import IAMMiconfigChecker
from config.dbConfig import get_config

def collect_and_check_iam(aws_cfg, scan_results, check_callback):
    total_checks = 0
    config = get_config()
    if not config:
        print("[ERROR] Could not load AWS configuration")
        return

    def _after_collect(err, data):
        if err:
            print(f"[IAM] Collection error: {err}")
            return
        if not data:
            print("[IAM] No data collected from get_iam_details")
            return

        # print(f"[IAM DEBUG] Collected data: {data}")

        def _after_check(err2, results, meta):
            nonlocal total_checks
            if err2:
                print(f"[IAM] Check error: {err2}")
                return
            if not results:
                print("[IAM] No results from IAMMiconfigChecker")
                scan_results.append({
                    "Category": "IAM",
                    "Check": "Configuration Check",
                    "Description": "No IAM issues found",
                    "Resource": "-",
                    "Status": "INFO",
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 1,
                    "Muted": 0,
                    "Remediation": "No action needed"
                })
                check_callback(1, {"INFO": 1})
                return

            for r in results:
                r["Category"] = "IAM"
                status = str(r.get("Status", "INFO")).upper()
                r["Status"] = status
                r["Critical"] = 0
                r["High"] = 0
                r["Medium"] = 0
                r["Low"] = 0
                r["Muted"] = 0
                if status == "FAIL":
                    r["Critical"] = 1
                elif status == "WARN":
                    r["High"] = 1
                elif status == "PASS":
                    r["Medium"] = 1
                elif status == "INFO":
                    r["Low"] = 1
                elif status in ["ERROR", "MUTED"]:
                    r["Muted"] = 1
                r.setdefault("Remediation", "N/A")

            # Debug part to check result
            # print(f"[IAM DEBUG] Check results: {results}")
            scan_results.extend(results)
            total_checks = len(results)
            status_counts = {"PASS": 0, "FAIL": 0, "HIGH": 0, "INFO": 0, "MUTED": 0, "ERROR": 0, "WARN": 0}
            for r in results:
                status = r["Status"]
                status_counts[status] = status_counts.get(status, 0) + 1
            
            check_callback(total_checks, status_counts)

        IAMMiconfigChecker().run(cache=data, settings=aws_cfg, callback=_after_check)

    get_iam_details(aws_cfg, _after_collect)