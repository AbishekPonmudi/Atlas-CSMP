from collector.aws.S3.getallbucket import get_bucket_policy
from plugins.aws.S3.Bucket_all_user_policy import S3BucketAllUsersPolicy

def collect_and_check_bucket(AWS_config, scan_results, check_callback):
    total_checks = 0
    def after_check(err, results, meta):
        nonlocal total_checks
        if err:
            print(f"[check] Error: {err}")
            return

        if not results:
            scan_results.append({
                "Category": "S3",
                "Check": "Bucket Check",
                "Description": "No buckets found",
                "Resource": "-",
                "Region": "-",
                "Status": "INFO",
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Muted": 0,
                "Remediation": "No remediation needed"
            })
            check_callback(1, {"INFO": 1})
            return

        scan_results.extend(results)
        total_checks = len(results)
        status_counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0, "ERROR": 0}
        for r in results:
            r.setdefault("Remediation", "N/A")  # Ensure Remediation exists
            status = r["Status"].upper()
            r["Status"] = status
            if status == "FAIL":
                r["Critical"] = 1
            elif status == "WARN":
                r["High"] = 1
            elif status == "PASS":
                r["Medium"] = 1
            elif status == "INFO":
                r["Low"] = 1
            elif status == "ERROR":
                r["Muted"] = 1
            # Ensure all fields are initialized
            for field in ["Critical", "High", "Medium", "Low", "Muted"]:
                r.setdefault(field, 0)
            status_counts[status] = status_counts.get(status, 0) + 1
        check_callback(total_checks, status_counts)

    def after_collect(err, buckets):
        if err:
            print(f"[collect] Error: {err}")
            return
        
        if not buckets:
            after_check(None, [], {})
            return

        cache = {
            "s3": {
                "listBuckets": {"data": buckets},
                "getBucketLocation": {
                    b["Name"]: {"data": {"LocationConstraint": b.get("Region", AWS_config["region"])}}
                    for b in buckets
                },
            }
        }
        checker = S3BucketAllUsersPolicy()
        checker.run(cache=cache, settings=AWS_config, callback=after_check)

    get_bucket_policy(AWS_config, after_collect)