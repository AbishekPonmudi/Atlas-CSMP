# This piece of code is belongs to Scybers and this code is done without using Any generative models
# copyrights@scybers

import json
from datetime import datetime, timedelta

class IAMMiconfigChecker:
    
    category_map = {
        'password_policy': 'Account',
        'root_mfa': 'Account',
        'user_mfa': 'User',
        'access_key_age': 'User',
        'wildcard_permissions': 'Permissions',
        'role_trust': 'Role',
    }
    
    def __init__(self):
        self.result = []
        self.remediation = {
           
            'password_policy': {
                0: "No action needed. Password policy meets standards.",
                1: "Ensure password length ≥ 14 and rotation ≤ 90 days per CIS.",
                2: "Enable a password policy.",
                3: "Enforce at least one uppercase, lowercase, number, and symbol."
               
            },
            'root_mfa': {
                0: "No action needed. Root MFA enabled.",
                1: "Check for the password strneght",
                2: "Enable MFA on the root account."
            },
            'user_mfa': {
                0: "User has MFA enabled.",
                1:" Check for the password strneght",
                2: "Require MFA on IAM user."
            },
            'access_key_age': {
                0: "No action needed. Access key age is within 90 days.",
                1: "Rotate access key older than 90 days."
            },
            'wildcard_permissions': {
                0: "No wildcard (*) permissions found.",
                1: "Review policy for wildcard actions or resources.",
                2: "Remove wildcard (*) from policy statements."
            },
            'role_trust': {
                0: "No wildcard trust principals.",
                1: "Restrict AssumeRolePolicy to specific principals."
            }
        }
    
    def add_result(self, check, status, desc, resource=''):
        self.results.append({
            "Category": self.category_map.get(check, "IAM"),
            'Check': check,
            'Status': ['PASS', 'WARN', 'FAIL', 'ERROR'][status],
            'Description': desc,
            'Resource': resource,
            'Remediation': self.remediation[check][status]
        })

    def check_password_policy(self, policy):
        if isinstance(policy, str) and policy.startswith("Error"):
            self.add_result('password_policy', 3, f"Error retrieving password policy: {policy}")
            return
        if not policy:
            self.add_result('password_policy', 3, "No password policy found")
            return

        errs = []
        status = 0
        if policy.get('MinimumPasswordLength', 0) < 14 or policy.get('MaxPasswordAge', 0) > 90:
            status = max(status, 1)
            errs.append("Length <14 or rotation >90d")
        if not (policy.get('RequireSymbols') and policy.get('RequireNumbers') and
                policy.get('RequireUppercaseCharacters') and policy.get('RequireLowercaseCharacters')):
            status = max(status, 2)
            errs.append("Missing complexity requirements")
        if not errs:
            status = 0
            desc = "Password policy meets all requirements"
        else:
            desc = "; ".join(errs)
        self.add_result('password_policy', status, desc)

    def check_root_mfa(self, summary):
        if summary.get('AccountMFAEnabled', 0) > 0:
            self.add_result('root_mfa', 0, "Root MFA is enabled")
        else:
            self.add_result('root_mfa', 2, "Root MFA is not enabled")

    def check_user_mfa(self, user):
        uname = user['UserName']
        if user['MFADevices']:
            self.add_result('user_mfa', 0, f"MFA enabled for user {uname}", uname)
        else:
            self.add_result('user_mfa', 2, f"No MFA devices for user {uname}", uname)

    def check_access_key_age(self, user):
        uname = user['UserName']
        for key in user['AccessKeys']:
            cd = user['CredentialReport']
            create_date = cd.get('access_key_1_active') and cd.get('access_key_1_last_rotated')
            # fallback: we parse the report date if available
            try:
                created = datetime.strptime(cd.get('access_key_1_last_rotated'), "%Y-%m-%dT%H:%M:%S+00:00")
                age = (datetime.utcnow() - created).days
            except Exception:
                age = 0
            if age > 90:
                self.add_result('access_key_age', 1, f"Access key {key['AccessKeyId']} age {age} days", uname)
            else:
                self.add_result('access_key_age', 0, f"Access key {key['AccessKeyId']} age {age} days", uname)

    def check_wildcard_permissions(self, entity):
        """
        entity can be a user dict or role dict with InlinePolicies & AttachedPolicies
        """
        name = entity.get('UserName') or entity.get('RoleName')
        pols = []

        # inline
        for doc in entity.get('InlinePolicies', {}).values():
            pols.append(doc)
        # attached: we only inspect the ARN string, not policy document
        for mp in entity.get('AttachedPolicies', []):
            # note: to do full, you'd Fetch policy document; here we flag broad ARNs
            if '*' in mp.get('PolicyArn', ''):
                self.add_result('wildcard_permissions', 1, f"Attached policy ARN wildcard for {name}", name)

        for doc in pols:
            stmts = doc.get('Statement', [])
            for s in stmts:
                acts = s.get('Action', [])
                if isinstance(acts, str):
                    acts = [acts]
                if any(a == '*' for a in acts):
                    self.add_result('wildcard_permissions', 2, f"Wildcard action in policy for {name}", name)
                    break

        # if none triggered, and no prior result for this entity:
        if not any(r['Resource'] == name and r['Check']=='wildcard_permissions' for r in self.results):
            self.add_result('wildcard_permissions', 0, f"No wildcard perms for {name}", name)

    def check_role_trust(self, role):
        name = role['RoleName']
        doc = role.get('AssumeRolePolicy', {})
        stmts = doc.get('Statement', [])
        for s in stmts:
            pr = s.get('Principal', {})
            if pr == '*' or '*' in json.dumps(pr):
                self.add_result('role_trust', 1, f"Wildcard trust in role {name}", name)
                return
        self.add_result('role_trust', 0, f"Trust policy is restricted for role {name}", name)

    def run(self, cache, settings, callback):
        self.results = []
        #data = cache.get('iam', {})
        data = cache
        # run checks
        self.check_password_policy(data.get('PasswordPolicy'))
        self.check_root_mfa(data.get('AccountSummary', {}))
        for u in data.get('Users', []):
            self.check_user_mfa(u)
            self.check_access_key_age(u)
            self.check_wildcard_permissions(u)
        for r in data.get('Roles', []):
            self.check_role_trust(r)
            self.check_wildcard_permissions(r)
        callback(None, self.results, {})
