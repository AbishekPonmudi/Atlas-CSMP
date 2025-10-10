import boto3
from botocore.exceptions import ClientError
import json
import time
from config.dbConfig import get_config

def get_iam_details(AWS_config, callback):
    try:
        iam = boto3.client('iam',
            aws_access_key_id=AWS_config['access_key'],
            aws_secret_access_key=AWS_config['secret_key'],
            region_name = AWS_config['region']
        )
        
        # Password policy rwetriveral 
        
        try:
            pwd_policy = iam.get_account_password_policy()['PasswordPolicy']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                pwd_policy = None
            else:
                pwd_policy = f"Error: {e.response['Error']['Message']}"
        
        # Account's summary
        
        try:
            acct_summary = iam.get_account_summary()['SummaryMap']
        except ClientError:
            acct_summary = {}
        
        user_report = {}
        
        try:
            # for generation credentials first
            
            iam.get_credential_report()
            report = None
            for _ in range(10): # trying to get report for 10 times to sure untill available 
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
                    user_report[vals[0]] = dict(zip(headers,vals))
                    
        except ClientError as e:
            user_report = {}
        
        # List users
        
        users = []
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for usr in page['Users']:
                uname = usr['UserName']
                
                # MFA devices
                try:
                    mfas = iam.list_mfa_devices(UserName=uname)['MFADevices']
                except ClientError:
                    mfas = []
                
                # AAccess keys
                try:
                    aks = iam.list_access_keys(UserName=uname)['AccessKeyMetadata']
                except ClientError:
                    aks = []
                
                # Inline Policy
                try:
                    inames = iam.list_user_policies(UserName=uname)['PolicyNames']
                    inline = {
                        name: iam.get_user_policy(UserName=uname,PolicyName=name)['PolicyDocument']
                        for name in inames
                    }
                except ClientError:
                    inline = {}
                    
                #Attached Policy
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
                    'CredentialReport': user_report.get(uname, {})
                })
       
       # List roles         
        roles = []
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for r in page['Roles']:
                rname = r['RoleName']
                # Trust policy
                try:
                    trust_doc = iam.get_role(RoleName=rname)['Role']['AssumeRolePolicyDocument']
                except ClientError:
                    trust_doc = {}
                # Inline
                try:
                    rnames = iam.list_role_policies(RoleName=rname)['PolicyNames']
                    inline = {
                        name: iam.get_role_policy(RoleName=rname, PolicyName=name)['PolicyDocument']
                        for name in rnames
                    }
                except ClientError:
                    inline = {}
                # Attached
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

if __name__ == "__main__":
    
    # this is for testing purpose
    
    def print_results(err, iam_user):
        if err:
            print(f"[ERROR] {err}")
            return