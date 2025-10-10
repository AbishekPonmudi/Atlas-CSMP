from tabulate import tabulate
from iam_collector import get_iam_config_details
from iam_policy import IAMMisconfigChecker


def collect_and_check_iam(aws_config):
    def after_collect(err, data):
        if err:
            print(f"Collection error: {err}")
            return

        def after_check(err, results, meta):
            if err:
                print(f"Check error: {err}")
                return
            headers = ["Category", "Check", "Description", "Resource", "Status", "Remediation"]
            rows = [[
                r["Category"], r["Check"], r["Description"],
                r["Resource"], r["Status"], r["Remediation"]
            ] for r in results]
            print(tabulate(rows, headers=headers, tablefmt="grid"))

        checker = IAMMisconfigChecker()
        checker.run(cache=data, settings=aws_config, callback=after_check)

    get_iam_config_details(aws_config, after_collect)


if __name__ == "__main__":

    from dbConfig import get_config
    aws_config = get_config()
    if not aws_config:
        print("[ERROR] Failed to load AWS config.")
        exit(1)
    collect_and_check_iam(aws_config)
