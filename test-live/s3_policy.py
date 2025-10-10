import json

class S3MisconfigChecker:
    def __init__(self):
        self.results = []
        self.remediation_map = {
            'policy_wildcard': {
                0: "No action needed. Bucket policy is secure.",
                1: "Review bucket policy conditions for wildcard principals and restrict to trusted identities.",
                2: "Remove wildcard principal (*) from bucket policy to prevent public access." or "no policy found",
                3: "Enable Policy for the Bucket or investigate why bucket policy could not be retrieved or parsed.",
                4: "No policy Found, Recommended to update the policy"

            },
            'encryption': {
                0: "No action needed. Bucket has server-side encryption enabled.",
                2: "Enable server-side encryption on the bucket.",
                3: "Investigate why encryption status could not be retrieved."
            },
            'mfa_delete': {
                0: "No action needed. MFA Delete is enabled.",
                1: "Consider enabling MFA Delete for additional security.",
                3: "Investigate why MFA Delete status could not be retrieved."
            },
            'access_logging': {
                0: "No action needed. Access logging is enabled.",
                1: "Enable server-side access logging for better monitoring.",
                3: "Investigate why access logging status could not be retrieved."
            },
            'public_access': {
                0: "No action needed. Public access is fully blocked.",
                1: "Enable all public access block settings to prevent public exposure.",
                3: "Investigate why public access block status could not be retrieved."
            },
            'acl': {
                0: "No action needed. ACL does not grant public access.",
                2: "Remove public access permissions from bucket ACL.",
                3: "Investigate why ACL could not be retrieved."
            }
        }

    def add_result(self, category, check_type, status, description, region, resource):
        self.results.append({
            "Category": category,
            "Check": check_type,
            "Description": description,
            "Resource": resource,
            "Region": region,
            "Status": ["PASS", "CONDITIONAL", "FAIL", "ERROR"][status],
            "Remediation": self.remediation_map[check_type][status]
        })

    def default_region(self, settings):
        return settings.get("region", "ap-south-1")

    def default_partition(self, settings):
        return settings.get("partition", "aws")

    def check_policy(self, policy_data, bucket_name, location, resource):
        if isinstance(policy_data, str) and policy_data.startswith("Error"):
            self.add_result("S3", "policy_wildcard", 3, f"Error retrieving policy for bucket: {bucket_name}", location, resource)
            return
        if not policy_data:
            self.add_result("S3", "policy_wildcard", 2, f"No policy found for bucket: {bucket_name}", location, resource)
            return
        if isinstance(policy_data, str):
            try:
                policy_data = json.loads(policy_data)
            except json.JSONDecodeError:
                self.add_result("S3", "policy_wildcard", 3, f"Invalid JSON policy for bucket: {bucket_name}", location, resource)
                return
        if not isinstance(policy_data, dict):
            self.add_result("S3", "policy_wildcard", 0, f"No valid policy found for bucket: {bucket_name}", location, resource)
            return

        statements = policy_data.get('Statement', [])
        if not statements:
            self.add_result("S3", "policy_wildcard", 1, f"Bucket policy does not contain any statements for: {bucket_name}", location, resource)
            return

        policy_messages = []
        policy_result = 0

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue
            principal = stmt.get('Principal')
            star = False
            if principal == '*' or principal == {'AWS': '*'} or principal == {'Service': '*'}:
                star = True
            elif isinstance(principal, dict):
                aws_pr = principal.get('AWS')
                svc_pr = principal.get('Service')
                if aws_pr == '*' or svc_pr == '*' or (isinstance(aws_pr, list) and '*' in aws_pr):
                    star = True
            if not star:
                continue
            action = stmt.get('Action')
            if stmt.get('Condition'):
                policy_result = max(policy_result, 1)
                policy_messages.append(f"Principal * allowed conditionally: {action}")
            else:
                policy_result = max(policy_result, 2)
                policy_messages.append(f"Principal * allowed unrestricted: {action}")

        if not policy_messages:
            self.add_result("S3", "policy_wildcard", 0, f"Bucket policy does not contain insecure allow statements for: {bucket_name}", location, resource)
        else:
            self.add_result("S3", "policy_wildcard", policy_result, ' '.join(policy_messages), location, resource)

    def check_encryption(self, encryption_data, bucket_name, location, resource):
        if encryption_data and isinstance(encryption_data, dict) and encryption_data.get("ServerSideEncryptionConfiguration"):
            self.add_result("S3", "encryption", 0, f"Server-side encryption enabled for bucket: {bucket_name}", location, resource)
        elif isinstance(encryption_data, str) and encryption_data.startswith("Error"):
            self.add_result("S3", "encryption", 3, f"Error retrieving encryption status for bucket: {bucket_name}", location, resource)
        else:
            self.add_result("S3", "encryption", 2, f"No server-side encryption configured for bucket: {bucket_name}", location, resource)

    def check_mfa_delete(self, mfa_status, bucket_name, location, resource):
        if mfa_status == "Enabled":
            self.add_result("S3", "mfa_delete", 0, f"MFA Delete enabled for bucket: {bucket_name}", location, resource)
        elif isinstance(mfa_status, str) and mfa_status.startswith("Error"):
            self.add_result("S3", "mfa_delete", 3, f"Error retrieving MFA Delete status for bucket: {bucket_name}", location, resource)
        else:
            self.add_result("S3", "mfa_delete", 1, f"MFA Delete not enabled for bucket: {bucket_name}", location, resource)

    def check_access_logging(self, logging_status, bucket_name, location, resource):
        if logging_status is True:
            self.add_result("S3", "access_logging", 0, f"Access logging enabled for bucket: {bucket_name}", location, resource)
        elif isinstance(logging_status, str) and logging_status.startswith("Error"):
            self.add_result("S3", "access_logging", 3, f"Error retrieving access logging status for bucket: {bucket_name}", location, resource)
        else:
            self.add_result("S3", "access_logging", 1, f"Access logging not enabled for bucket: {bucket_name}", location, resource)

    def check_public_access(self, block_config, bucket_name, location, resource):
        if (block_config and isinstance(block_config, dict) and
            block_config.get("BlockPublicAcls") and
            block_config.get("IgnorePublicAcls") and
            block_config.get("BlockPublicPolicy") and
            block_config.get("RestrictPublicBuckets")):
            self.add_result("S3", "public_access", 0, f"Public access fully blocked for bucket: {bucket_name}", location, resource)
        elif isinstance(block_config, str) and block_config.startswith("Error"):
            self.add_result("S3", "public_access", 3, f"Error retrieving public access block status for bucket: {bucket_name}", location, resource)
        else:
            self.add_result("S3", "public_access", 1, f"Public access block settings incomplete for bucket: {bucket_name}", location, resource)

    def check_acl(self, acl_data, bucket_name, location, resource):
        if isinstance(acl_data, str) and acl_data.startswith("Error"):
            self.add_result("S3", "acl", 3, f"Error retrieving ACL for bucket: {bucket_name}", location, resource)
            return
        grants = acl_data.get("Grants", [])
        public_access = False
        for grant in grants:
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                public_access = True
                break
        if public_access:
            self.add_result("S3", "acl", 2, f"ACL grants public access for bucket: {bucket_name}", location, resource)
        else:
            self.add_result("S3", "acl", 0, f"No public access via ACL for bucket: {bucket_name}", location, resource)

    def run(self, cache, settings, callback):
        self.results = []
        partition = self.default_partition(settings)
        default_region = self.default_region(settings)

        bucket_list = cache['s3']['listBuckets'].get('data', [])
        if not bucket_list:
            self.add_result("S3", "general", 3, "No S3 buckets to check", default_region, "")
            return callback(None, self.results, {})

        for bucket in bucket_list:
            name = bucket.get('Name')
            if not name:
                continue
            resource = f"arn:{partition}:s3:::{name}"
            location = bucket.get('Region', default_region)

            
            self.check_policy(bucket.get('Policy'), name, location, resource)
            self.check_encryption(bucket.get('Encryption'), name, location, resource)
            self.check_mfa_delete(bucket.get('MFADelete'), name, location, resource)
            self.check_access_logging(bucket.get('AccessLogging'), name, location, resource)
            self.check_public_access(bucket.get('BlockPublicAccess'), name, location, resource)
            self.check_acl(bucket.get('ACL'), name, location, resource)

        callback(None, self.results, {})