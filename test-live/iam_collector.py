# iam_collector.py

import json
import time
import boto3
from botocore.exceptions import ClientError

def get_iam_config_details(aws_config, callback):
    # """
    # Collects:
    #   - Account password policy
    #   - Account summary (for root MFA)
    #   - Credential report (for users’ access keys + key age)
    #   - Users (MFA devices, inline & attached policies)
    #   - Roles (trust policy + inline & attached policies)
    # """
    try:
        iam = boto3.client(
            'iam',
            aws_access_key_id=aws_config.get('access_key'),
            aws_secret_access_key=aws_config.get('secret_key'),
            region_name=aws_config.get('region')
        )
        try:
            pwd_policy = iam.get_account_password_policy()['PasswordPolicy']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                pwd_policy = None
            else:
                pwd_policy = f"Error: {e.response['Error']['Message']}"

        try:
            acct_summary = iam.get_account_summary()['SummaryMap']
        except ClientError:
            acct_summary = {}

        users_report = {}
        try:
            iam.generate_credential_report()
            report = None
            for _ in range(10):
                rep = iam.get_credential_report()
                if rep.get('State') == 'COMPLETE' and 'Content' in rep:
                    report = rep
                    break
                time.sleep(1)
            if report and report.get('Content'):
                lines = report['Content'].decode('utf-8').splitlines()
                headers = lines[0].split(',')
                for row in lines[1:]:
                    vals = row.split(',')
                    users_report[vals[0]] = dict(zip(headers, vals))
        except ClientError:
            users_report = {}

        users = []
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for u in page['Users']:
                uname = u['UserName']
                try:
                    mfas = iam.list_mfa_devices(UserName=uname)['MFADevices']
                except ClientError:
                    mfas = []
                try:
                    aks = iam.list_access_keys(UserName=uname)['AccessKeyMetadata']
                except ClientError:
                    aks = []
                try:
                    inames = iam.list_user_policies(UserName=uname)['PolicyNames']
                    inline = {
                        name: iam.get_user_policy(UserName=uname, PolicyName=name)['PolicyDocument']
                        for name in inames
                    }
                except ClientError:
                    inline = {}
                try:
                    attached = iam.list_attached_user_policies(UserName=uname)['AttachedPolicies']
                except ClientError:
                    attached = []

                users.append({
                    'UserName': uname,
                    'MFADevices': mfas,
                    'AccessKeys': aks,
                    'InlinePolicies': inline,
                    'AttachedPolicies': attached,
                    'CredentialReport': users_report.get(uname, {})
                })

        roles = []
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for r in page['Roles']:
                rname = r['RoleName']
                try:
                    trust_doc = iam.get_role(RoleName=rname)['Role']['AssumeRolePolicyDocument']
                except ClientError:
                    trust_doc = {}
                try:
                    rnames = iam.list_role_policies(RoleName=rname)['PolicyNames']
                    inline = {
                        name: iam.get_role_policy(RoleName=rname, PolicyName=name)['PolicyDocument']
                        for name in rnames
                    }
                except ClientError:
                    inline = {}
                try:
                    attached = iam.list_attached_role_policies(RoleName=rname)['AttachedPolicies']
                except ClientError:
                    attached = []

                roles.append({
                    'RoleName': rname,
                    'AssumeRolePolicy': trust_doc,
                    'InlinePolicies': inline,
                    'AttachedPolicies': attached
                })

        data = {
            'PasswordPolicy': pwd_policy,
            'AccountSummary': acct_summary,
            'Users': users,
            'Roles': roles
        }
        callback(None, data)

    except Exception as e:
        callback(str(e), {})
