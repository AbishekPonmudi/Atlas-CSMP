from tabulate import tabulate
import os
from s3_collector import get_s3_config_details
from s3_policy import S3MisconfigChecker

def collect_and_check_buckets(aws_config):
    def after_collect(err, buckets):
        if err:
            print(f"Collection error 1: {err}")
            return

        cache = {
            's3': {
                'listBuckets': {
                    'data': buckets
                },
                'getBucketLocation': {
                    b['Name']: {
                        'data': {
                            'LocationConstraint': b.get('Region', aws_config['region'])
                        }
                    } for b in buckets
                }
            }
        }

        def after_check(err, results, meta):
            if err:
                print(f"Check error: {err}")
                return

            headers = ["Category", "Check", "Description", "Resource", "Region", "Status", "Remediation"]
            rows = [[
                r["Category"],
                r["Check"],
                r["Description"],
                r["Resource"],
                r["Region"],
                r["Status"],
                r["Remediation"]
            ] for r in results]
            print(tabulate(rows, headers=headers, tablefmt="grid"))

        checker = S3MisconfigChecker()
        checker.run(
            cache=cache,
            settings=aws_config,
            callback=after_check
        )

    get_s3_config_details(aws_config, after_collect)

if __name__ == "__main__":
    try:
        from config.dbConfig import get_config
    except ImportError:
        AWSconfig = get_config()
        access_key = AWSconfig['access_key'],
        secret_key = AWSconfig['secret_key'],
        region = AWSconfig['region']            

    aws_config = get_config()
    print(aws_config['access_key'])
    print(aws_config['secret_key'])
    if not aws_config:
        print("[ERROR] Failed to load AWS config.")
        exit(1)
    collect_and_check_buckets(aws_config)