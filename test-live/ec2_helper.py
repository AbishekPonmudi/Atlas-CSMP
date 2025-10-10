# helper_ec2.py — Finalized version with proper table + empty-check handling

import os, sys
from tabulate import tabulate
from config.dbConfig import get_config

script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from ec2_collector import get_ec2_config_details
from ec2_policy    import EC2MisconfigChecker
from config.dbConfig      import get_config


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

def collect_and_check_ec2(aws_cfg):
    def after_collect(err, data):
        if err:
            print(f"[ERROR] EC2 collection: {err}")
            return

        if not data.get("Instances"):
            print("[INFO] No EC2 instances found in this region/account.")
            return

        cache = {'ec2': data}

        def after_check(err, results, meta):
            if err:
                print(f"[ERROR] EC2 checks: {err}")
                return

            headers = ["Category", "Check", "Description", "Resource", "Region", "Status", "Remediation"]
            rows = []

            for r in results:
                check = r["Check"]
                cat   = CATEGORY_MAP.get(check, "General")
                res   = r.get("Resource", "")
                region = ""
                # Try to extract region from resource or use fallback
                for inst in data.get("Instances", []):
                    if inst.get("InstanceId") == res or inst.get("KeyName") == res or inst.get("ImageId") == res:
                        region = inst.get("Region")
                        break
                row = [
                    cat,
                    check,
                    r["Description"],
                    res,
                    region or aws_cfg.get("region"),
                    r["Status"],
                    r["Remediation"]
                ]
                rows.append(row)

            print("\n" + tabulate(rows, headers=headers, tablefmt="grid"))

        EC2MisconfigChecker().run(cache=cache, settings=aws_cfg, callback=after_check)

    get_ec2_config_details(aws_cfg, after_collect)


if __name__ == "__main__":
    cfg = get_config()
    if not cfg.get('access_key') or not cfg.get('secret_key'):
        print("[ERROR] AWS config missing in dbConfig.py")
        sys.exit(1)

    collect_and_check_ec2(cfg)
