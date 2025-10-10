from collector.aws.EC2.ec2_collector import get_ec2_details
from plugins.aws.EC2.ec2_policy import EC2MisconfigChecker
from config.dbConfig import get_config
import time

CATEGORY_MAP = {
    'public_ip': "Public Access",
    'sg_open': "Public Access",
    'elastic_ip': "Public Access",
    'instance_profile': "IAM Role & Access",
    'role_wildcard': "IAM Role & Access",
    'unused_role': "IAM Role & Access",
    'ebs_encrypt': "Storage & Encryption",
    'ami_public': "Storage & Encryption",
    'snapshot_encrypt': "Storage & Encryption",
    'cloudtrail': "Monitoring & Logging",
    'flowlogs': "Monitoring & Logging",
    'detailed_monitor': "Monitoring & Logging",
    'outdated_ami': "Patch & Vulnerability",
    'ssm_managed': "Patch & Vulnerability",
    'stale_keypair': "SSH Access & Key Mgmt",
    'unused_instance': "Lifecycle & Cost"
}

def collect_and_check_ec2(aws_cfg, scan_results, check_callback):
    total_checks = 0
    config = get_config()
    if not config:
        scan_results.append({
            "Category": "EC2",
            "Check": "Configuration Check",
            "Description": "Could not load AWS configuration",
            "Resource": "-",
            "Status": "ERROR",
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Muted": 1,
            "Remediation": "Ensure AWS credentials are configured correctly"
        })
        check_callback(1, {"ERROR": 1})
        return
    
    def after_collect(err, data):
        nonlocal total_checks
        if err:
            scan_results.append({
                "Category": "EC2",
                "Check": "EC2 Collection",
                "Description": f"Error collecting EC2 data: {err}",
                "Resource": "-",
                "Status": "ERROR",
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Muted": 1,
                "Remediation": "Check AWS credentials and permissions"
            })
            check_callback(1, {"ERROR": 1})
            return

        if not data.get("Instances"):
            scan_results.append({
                "Category": "EC2",
                "Check": "EC2 Instances",
                "Description": "No EC2 instances found in this region/account",
                "Resource": "-",
                "Status": "INFO",
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Muted": 1,
                "Remediation": "No action needed"
            }) 
            check_callback(1, {"INFO": 1})
            return

        cache = {'ec2': data}

        def after_check(err, results, meta):
            if err:
                scan_results.append({
                    "Category": "EC2",
                    "Check": "EC2 Checks",
                    "Description": f"Error running EC2 checks: {err}",
                    "Resource": "-",
                    "Status": "ERROR",
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Muted": 1,
                    "Remediation": "Check EC2 check configuration"
                })
                check_callback(1, {"ERROR": 1})
                return
            if not results:
                scan_results.append({
                    "Category": "EC2",
                    "Check": "Configuration Check",
                    "Description": "No EC2 issues found",
                    "Resource": "-",
                    "Status": "INFO",
                    "Critical": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Muted": 1,
                    "Remediation": "No action needed"
                })
                check_callback(1, {"INFO": 1})

            status_counts = {"PASS": 0, "FAIL": 0, "HIGH": 0, "INFO": 0, "MUTED": 0, "ERROR": 0, "WARN": 0}
            for r in results:
                r["Category"] = CATEGORY_MAP.get(r.get("check", "unknown"), "EC2")  # Fallback to "EC2" if "check" is missing
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

                scan_results.append(r)
                status_counts[status] = status_counts.get(status, 0) + 1
                check_callback(1, {status: 1})  
                time.sleep(0.1) 

            total_checks = len(results)
            check_callback(total_checks, status_counts)

        EC2MisconfigChecker().run(cache=cache, settings=aws_cfg, callback=after_check)

    get_ec2_details(aws_cfg, after_collect)