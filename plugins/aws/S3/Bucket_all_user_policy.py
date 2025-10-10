# This piece of code is belongs to Scybers and this code is done without using Any generative models
# copyrights@scybers

import json
import re

class S3BucketAllUsersPolicy:
    def __init__(self):
        self.results = []
        self.remediation_map = {
            'policy_wildcard': {
                0: "Bucket policy does not allow unrestricted public access. No action required.",
                1: "Bucket policy contains wildcard principals (*) allowing public access. \nRemediation: Remove or restrict wildcard principals in bucket policy. Implement condition blocks with IP restrictions, VPC endpoints, or specific IAM principals. Review AWS documentation for secure bucket policies.",
                2: "No bucket policy found or bucket policy allows unrestricted access.\nRemediation: Create and attach a restrictive bucket policy that explicitly denies public access. Use AWS S3 console or CLI to implement least privilege access controls.",
                3: "Unable to retrieve or parse bucket policy. \nRemediation: Verify bucket exists and IAM permissions allow policy retrieval. Check for malformed JSON in existing policy. Use AWS CloudTrail to investigate access issues."
            },
            'encryption': {
                0: "Server-side encryption is properly configured. No action required.",
                1: "Server-side encryption is not enabled. \nRemediation: Enable default encryption using AWS KMS or S3-managed keys. \n  Use AWS CLI command 'aws s3api put-bucket-encryption' or configure through S3 console. Implement bucket policy to deny unencrypted uploads.",
                2: "Encryption configuration could not be retrieved. \nRemediation: Verify IAM permissions for s3:GetEncryptionConfiguration. \n  Check bucket existence and region configuration."
            },
            'mfa_delete': {
                0: "MFA Delete is enabled for enhanced security. No action required.",
                1: "MFA Delete is not enabled. \nRemediation: Enable MFA Delete for bucket versioning protection. \n  Use AWS CLI with MFA token: 'aws s3api put-bucket-versioning --mfa'. Ensure bucket versioning is enabled first.",
                2: "MFA Delete status could not be determined. \nRemediation: Verify bucket versioning status and \n  IAM permissions for s3:GetBucketVersioning."
            },
            'access_logging': {
                0: "Server access logging is enabled for audit trail. No action required.",
                1: "Server access logging is not enabled. \nRemediation: Configure server access logging to dedicated \n  logging bucket. Use AWS CLI 'aws s3api put-bucket-logging' or S3 console. Ensure logging bucket has appropriate lifecycle policies.",
                2: "Access logging status could not be retrieved. \nRemediation: Verify IAM permissions for \n  s3:GetBucketLogging and check bucket accessibility."
            },
            'public_access': {
                0: "All public access block settings are enabled. No action required.",
                1: "Public access block settings are incomplete or disabled. \nRemediation: Enable all four public access block settings: \n  BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets. Use AWS CLI 'aws s3api put-public-access-block' or S3 console.",
                2: "Public access block configuration could not be retrieved. \nRemediation: Verify IAM permissions for s3:GetBucketPublicAccessBlock \n  and bucket accessibility."
            },
            'acl': {
                0: "Bucket ACL does not grant public access. No action required.",
                1: "Bucket ACL grants public access to AllUsers or AuthenticatedUsers. \nRemediation: Remove public ACL grants using AWS CLI 'aws s3api put-bucket-acl' \n  with private ACL. Use bucket policies instead of ACLs for access control.",
                2: "Bucket ACL could not be retrieved. \nRemediation: Verify IAM permissions for s3:GetBucketAcl and check bucket accessibility."
            },
            'versioning': {
                0: "Bucket versioning is enabled for data protection. No action required.",
                1: "Bucket versioning is not enabled. \nRemediation: Enable versioning using AWS CLI 'aws s3api put-bucket-versioning'\n   or S3 console. Implement lifecycle policies to manage version costs.",
                2: "Bucket versioning status could not be retrieved. \nRemediation: Verify IAM permissions for s3:GetBucketVersioning and bucket accessibility."
            },
            'lifecycle': {
                0: "Lifecycle configuration is properly set. No action required.",
                1: "No lifecycle configuration found. \nRemediation: Implement lifecycle policies to automatically transition objects \n  to cheaper storage classes and delete expired versions. Use S3 console or AWS CLI 'aws s3api put-bucket-lifecycle-configuration'.",
                2: "Lifecycle configuration could not be retrieved. \nRemediation: Verify IAM permissions for s3:GetLifecycleConfiguration\n   and bucket accessibility."
            },
            'notification': {
                0: "Bucket notifications are properly configured. No action required.",
                1: "No event notifications configured. \nRemediation: Configure bucket notifications for security monitoring. Set up \n  notifications to CloudWatch, SNS, or SQS for object-level operations.",
                2: "Notification configuration could not be retrieved. \nRemediation: Verify IAM permissions for s3:GetBucketNotification\n   and bucket accessibility."
            },
            'transfer_acceleration': {
                0: "Transfer acceleration configuration is appropriate. No action required.",
                1: "Transfer acceleration status could not be determined. \nRemediation: Review if transfer acceleration is needed for your \n  use case. Enable if required for global uploads.",
                2: "Transfer acceleration configuration could not be retrieved. \nRemediation: Verify IAM permissions and bucket accessibility."
            },
            'object_lock': {
                0: "Object Lock configuration is appropriate for compliance requirements. No action required.",
                1: "Object Lock is not configured for compliance-sensitive data. \nRemediation: Enable Object Lock if required for \n  regulatory compliance. Note: This requires versioning and can only be enabled during bucket creation.",
                2: "Object Lock configuration could not be retrieved. \nRemediation: Verify IAM permissions for s3:GetObjectLockConfiguration\n   and bucket accessibility."
            },
            'website_config': {
                0: "No static website hosting configuration found. No action required.",
                1: "Static website hosting is enabled without proper security controls. \nRemediation: Disable static website hosting if not needed.\n  If required, ensure proper CloudFront distribution and access controls are in place.",
                2: "Website configuration could not be retrieved. \nRemediation: Verify IAM permissions for \n  s3:GetBucketWebsite and bucket accessibility."
            },
            'cors': {
                0: "CORS configuration is appropriate or not configured. No action required.",
                1: "CORS configuration allows overly permissive cross-origin access. \nRemediation: Review and restrict CORS rules to \n  specific domains and methods. Remove wildcard (*) origins in production environments.",
                2: "CORS configuration could not be retrieved. \nRemediation: Verify IAM permissions for \n  s3:GetBucketCors and bucket accessibility."
            }
        }

    def add_result(self, category, check_type, status, description, region, resource):
        self.results.append({
            "Category": category,
            "Check": check_type,
            "Description": description,
            "Resource": resource,
            "Region": region,
            "Status": ["PASS", "WARN", "FAIL", "ERROR"][status], 
            "Remediation": self.remediation_map[check_type][status]
        })

    def default_region(self, settings):
        return settings.get("region", "ap-south-1")

    def default_partition(self, settings):
        return settings.get("partition", "aws")

    def check_policy(self, policy_data, bucket_name, location, resource):
        """CIS 2.1.1: Ensure S3 bucket policy does not allow wildcard principal"""
        if isinstance(policy_data, str) and policy_data.startswith("Error"):
            self.add_result("S3", "policy_wildcard", 3, f"Error retrieving policy for bucket", location, resource)
            return
        
        if not policy_data:
            self.add_result("S3", "policy_wildcard", 2, f"No bucket policy found", location, resource)
            return

        if isinstance(policy_data, str):
            try:
                policy_data = json.loads(policy_data)
            except json.JSONDecodeError:
                self.add_result("S3", "policy_wildcard", 3, f"Invalid JSON policy for bucket", location, resource)
                return

        if not isinstance(policy_data, dict):
            self.add_result("S3", "policy_wildcard", 2, f"No valid policy found for bucket", location, resource)
            return

        statements = policy_data.get('Statement', [])
        if not statements:
            self.add_result("S3", "policy_wildcard", 2, f"Bucket policy contains no statements for", location, resource)
            return

        has_wildcard_issues = False
        policy_messages = []

        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue
                
            principal = stmt.get('Principal')
            has_wildcard = False
            
            # Check for various wildcard patterns
            if principal == '*':
                has_wildcard = True
            elif isinstance(principal, dict):
                for key, value in principal.items():
                    if value == '*' or (isinstance(value, list) and '*' in value):
                        has_wildcard = True
                        break
            elif isinstance(principal, list) and '*' in principal:
                has_wildcard = True

            if has_wildcard:
                action = stmt.get('Action', 'Unknown')
                condition = stmt.get('Condition')
                
                if condition:
                    # Even with conditions, wildcard principals are risky
                    policy_messages.append(f"Wildcard principal (*) with conditions for action: {action}")
                    has_wildcard_issues = True
                else:
                    policy_messages.append(f"Unrestricted wildcard principal (*) for action: {action}")
                    has_wildcard_issues = True

        if has_wildcard_issues:
            self.add_result("S3", "policy_wildcard", 1, f"Bucket policy allows wildcard access: {'; '.join(policy_messages)}", location, resource)
        else:
            self.add_result("S3", "policy_wildcard", 0, f"Bucket policy does not contain wildcard principals for", location, resource)

    def check_encryption(self, encryption_data, bucket_name, location, resource):
        """CIS 2.1.2: Ensure S3 bucket has server-side encryption enabled"""
        if isinstance(encryption_data, str) and encryption_data.startswith("Error"):
            self.add_result("S3", "encryption", 3, f"Error retrieving encryption status for bucket", location, resource)
            return

        if encryption_data and isinstance(encryption_data, dict):
            sse_config = encryption_data.get("ServerSideEncryptionConfiguration", {})
            rules = sse_config.get("Rules", [])
            
            if rules and any(rule.get("ApplyServerSideEncryptionByDefault") for rule in rules):
                self.add_result("S3", "encryption", 0, f"Server-side encryption enabled for bucket", location, resource)
            else:
                self.add_result("S3", "encryption", 2, f"Server-side encryption not properly configured for bucket", location, resource)
        else:
            self.add_result("S3", "encryption", 1, f"No server-side encryption configured for bucket", location, resource)

    def check_mfa_delete(self, mfa_status, versioning_data, bucket_name, location, resource):
        """CIS 2.1.3: Ensure S3 bucket has MFA Delete enabled"""
        if isinstance(mfa_status, str) and mfa_status.startswith("Error"):
            self.add_result("S3", "mfa_delete", 3, f"Error retrieving MFA Delete status for bucket", location, resource)
            return

        # Check if versioning is enabled first
        if isinstance(versioning_data, dict):
            versioning_status = versioning_data.get("Status", "Disabled")
            mfa_delete_status = versioning_data.get("MfaDelete", "Disabled")
        else:
            versioning_status = "Disabled"
            mfa_delete_status = "Disabled"

        if versioning_status == "Enabled" and mfa_delete_status == "Enabled":
            self.add_result("S3", "mfa_delete", 0, f"MFA Delete enabled for bucket", location, resource)
        else:
            self.add_result("S3", "mfa_delete", 1, f"MFA Delete not enabled for bucket (Versioning: {versioning_status}, MFA Delete: {mfa_delete_status})", location, resource)

    def check_access_logging(self, logging_status, bucket_name, location, resource):
        """CIS 2.1.4: Ensure S3 bucket has access logging enabled"""
        if isinstance(logging_status, str) and logging_status.startswith("Error"):
            self.add_result("S3", "access_logging", 3, f"Error retrieving access logging status for bucket", location, resource)
            return

        if isinstance(logging_status, dict) and logging_status.get("LoggingEnabled"):
            target_bucket = logging_status["LoggingEnabled"].get("TargetBucket")
            if target_bucket:
                self.add_result("S3", "access_logging", 0, f"Access logging enabled for bucket (Target: {target_bucket})", location, resource)
            else:
                self.add_result("S3", "access_logging", 2, f"Access logging configured but no target bucket specified for", location, resource)
        else:
            self.add_result("S3", "access_logging", 1, f"Access logging not enabled for bucket", location, resource)

    def check_public_access(self, block_config, bucket_name, location, resource):
        """CIS 2.1.5: Ensure S3 bucket public access block is set"""
        if isinstance(block_config, str) and block_config.startswith("Error"):
            self.add_result("S3", "public_access", 3, f"Error retrieving public access block status for bucket", location, resource)
            return

        if isinstance(block_config, dict):
            required_settings = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            enabled_settings = [setting for setting in required_settings if block_config.get(setting, False)]
            
            if len(enabled_settings) == 4:
                self.add_result("S3", "public_access", 0, f"All public access block settings enabled for bucket", location, resource)
            else:
                missing_settings = [setting for setting in required_settings if not block_config.get(setting, False)]
                self.add_result("S3", "public_access", 2, f"Public access block incomplete for bucket. Missing: {', '.join(missing_settings)}", location, resource)
        else:
            self.add_result("S3", "public_access", 1, f"Public access block not configured for bucket", location, resource)

    def check_acl(self, acl_data, bucket_name, location, resource):
        """Check S3 bucket ACL for public access grants"""
        if isinstance(acl_data, str) and acl_data.startswith("Error"):
            self.add_result("S3", "acl", 3, f"Error retrieving ACL for bucket", location, resource)
            return

        if not isinstance(acl_data, dict):
            self.add_result("S3", "acl", 3, f"Invalid ACL data for bucket", location, resource)
            return

        grants = acl_data.get("Grants", [])
        public_grants = []
        
        for grant in grants:
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "")
            
            if grantee.get("Type") == "Group":
                uri = grantee.get("URI", "")
                if "AllUsers" in uri:
                    public_grants.append(f"AllUsers:{permission}")
                elif "AuthenticatedUsers" in uri:
                    public_grants.append(f"AuthenticatedUsers:{permission}")

        if public_grants:
            self.add_result("S3", "acl", 1, f"Public ACL grants found for bucket - {', '.join(public_grants)}", location, resource)
        else:
            self.add_result("S3", "acl", 0, f"No public ACL grants for bucket", location, resource)

    def check_versioning(self, versioning_data, bucket_name, location, resource):
        """Check if S3 bucket versioning is enabled"""
        if isinstance(versioning_data, str) and versioning_data.startswith("Error"):
            self.add_result("S3", "versioning", 2, f"Error retrieving versioning status for bucket", location, resource)
            return

        if isinstance(versioning_data, dict):
            status = versioning_data.get("Status", "Disabled")
            if status == "Enabled":
                self.add_result("S3", "versioning", 0, f"Versioning enabled for bucket", location, resource)
            else:
                self.add_result("S3", "versioning", 1, f"Versioning not enabled for bucket (Status: {status})", location, resource)
        else:
            self.add_result("S3", "versioning", 1, f"Versioning not configured for bucket", location, resource)

    def check_lifecycle(self, lifecycle_data, bucket_name, location, resource):
        """Check if S3 bucket has lifecycle configuration"""
        if isinstance(lifecycle_data, str) and lifecycle_data.startswith("Error"):
            self.add_result("S3", "lifecycle", 3, f"Error retrieving lifecycle configuration for bucket", location, resource)
            return

        if isinstance(lifecycle_data, dict) and lifecycle_data.get("Rules"):
            rules = lifecycle_data["Rules"]
            active_rules = [rule for rule in rules if rule.get("Status") == "Enabled"]
            if active_rules:
                self.add_result("S3", "lifecycle", 0, f"Lifecycle configuration active for bucket ({len(active_rules)} rules)", location, resource)
            else:
                self.add_result("S3", "lifecycle", 2, f"Lifecycle rules exist but none are enabled for bucket", location, resource)
        else:
            self.add_result("S3", "lifecycle", 1, f"No lifecycle configuration for bucket", location, resource)

    def check_notification(self, notification_data, bucket_name, location, resource):
        """Check S3 bucket notification configuration"""
        if isinstance(notification_data, str) and notification_data.startswith("Error"):
            self.add_result("S3", "notification", 3, f"Error retrieving notification configuration for bucket", location, resource)
            return

        if isinstance(notification_data, dict):
            has_notifications = any([
                notification_data.get("TopicConfigurations"),
                notification_data.get("QueueConfigurations"),
                notification_data.get("LambdaConfigurations"),
                notification_data.get("CloudWatchConfigurations")
            ])
            
            if has_notifications:
                self.add_result("S3", "notification", 0, f"Event notifications configured for bucket", location, resource)
            else:
                self.add_result("S3", "notification", 2, f"No event notifications configured for bucket", location, resource)
        else:
            self.add_result("S3", "notification", 1, f"No notification configuration for bucket", location, resource)

    def check_website_config(self, website_data, bucket_name, location, resource):
        """Check if S3 bucket has website hosting enabled"""
        if isinstance(website_data, str) and website_data.startswith("Error"):
            if "NoSuchWebsiteConfiguration" in website_data:
                self.add_result("S3", "website_config", 0, f"No website hosting configuration for bucket (Good)", location, resource)
            else:
                self.add_result("S3", "website_config", 3, f"Error retrieving website configuration for bucket", location, resource)
            return

        if isinstance(website_data, dict) and (website_data.get("IndexDocument") or website_data.get("RedirectAllRequestsTo")):
            self.add_result("S3", "website_config", 1, f"Static website hosting enabled for bucket", location, resource)
        else:
            self.add_result("S3", "website_config", 0, f"No website hosting configuration for bucket", location, resource)

    def check_cors(self, cors_data, bucket_name, location, resource):
        """Check S3 bucket CORS configuration"""
        if isinstance(cors_data, str) and cors_data.startswith("Error"):
            if "NoSuchCORSConfiguration" in cors_data:
                self.add_result("S3", "cors", 0, f"No CORS configuration for bucket", location, resource)
            else:
                self.add_result("S3", "cors", 3, f"Error retrieving CORS configuration for bucket", location, resource)
            return

        if isinstance(cors_data, dict) and cors_data.get("CORSRules"):
            rules = cors_data["CORSRules"]
            permissive_rules = []
            
            for rule in rules:
                allowed_origins = rule.get("AllowedOrigins", [])
                allowed_methods = rule.get("AllowedMethods", [])
                
                if "*" in allowed_origins:
                    permissive_rules.append(f"Wildcard origin with methods: {', '.join(allowed_methods)}")
                    
            if permissive_rules:
                self.add_result("S3", "cors", 1, f"Permissive CORS configuration for bucket - {'; '.join(permissive_rules)}", location, resource)
            else:
                self.add_result("S3", "cors", 0, f"CORS configuration appears restrictive for bucket", location, resource)
        else:
            self.add_result("S3", "cors", 0, f"No CORS configuration for bucket", location, resource)

    def run(self, cache, settings, callback):
        self.results = []
        partition = self.default_partition(settings)
        default_region = self.default_region(settings)

        # Get bucket list from cache
        bucket_list = cache.get('s3', {}).get('listBuckets', {}).get('data', [])
        
        if not bucket_list:
            self.add_result("S3", "policy_wildcard", 1, "No S3 buckets found to analyze", default_region, f"arn:{partition}:s3:::*")
            return callback(None, self.results, {})

        for bucket in bucket_list:
            name = bucket.get('Name')
            if not name:
                continue
                
            resource = f"arn:{partition}:s3:::{name}"
            location = bucket.get('Region', default_region)

            # Core CIS benchmark checks all auto checks ups
            self.check_policy(bucket.get('Policy'), name, location, resource)
            self.check_encryption(bucket.get('Encryption'), name, location, resource)
            self.check_public_access(bucket.get('BlockPublicAccess'), name, location, resource)
            self.check_acl(bucket.get('ACL'), name, location, resource)
            versioning_data = bucket.get('Versioning')
            self.check_versioning(versioning_data, name, location, resource)
            self.check_mfa_delete(bucket.get('MFADelete'), versioning_data, name, location, resource)
            self.check_access_logging(bucket.get('AccessLogging'), name, location, resource)
            self.check_lifecycle(bucket.get('Lifecycle'), name, location, resource)
            self.check_notification(bucket.get('Notifications'), name, location, resource)
            self.check_website_config(bucket.get('WebsiteConfiguration'), name, location, resource)
            self.check_cors(bucket.get('CORS'), name, location, resource)

        return callback(None, self.results, {})