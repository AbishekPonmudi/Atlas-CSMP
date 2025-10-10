# This piece of code is belongs to Scybers and this code is done without using Any generative models
# copyrights@scybers

from datetime import datetime, timedelta
import json
from collections import defaultdict

class EC2MisconfigChecker:
    def __init__(self):
        self.results = []
        self.remediation_map = {
            'public_ip': {
                0: "No action needed. Instance has no public IP or is properly justified for public access.",
                1: "Consider reviewing if public IP is necessary. \nUse private subnets with NAT Gateway for outbound connectivity.",
                2: "Remove unnecessary public IP assignment. \nMove instance to private subnet and use bastion host or VPN for access.",
                3: "Investigate why public IP status could not be determined.",
                4: "Instance data incomplete - unable to verify public IP configuration."
            },
            'sg_open_ssh_rdp': {
                0: "No action needed. Security groups properly restrict SSH/RDP access from internet.",
                1: "Review security group rules. Consider restricting \nSSH/RDP access to specific IP ranges instead of 0.0.0.0/0.",
                2: "Immediately restrict SSH (22) and RDP (3389) \naccess from 0.0.0.0/0. Use bastion hosts, VPN, or specific IP ranges.",
                3: "Investigate why security group configuration could not be retrieved.",
                4: "Security group data incomplete - unable to verify ingress rules."
            },
            'sg_open_all_ports': {
                0: "No action needed. Security groups do not allow \nunrestricted access to all ports.",
                2: "Remove rules allowing 0.0.0.0/0 access to all ports. \nImplement principle of least privilege.",
                3: "Investigate why security group configuration could not be retrieved.",
                4: "Security group data incomplete - unable to verify port access rules."
            },
            'elastic_ip_unused': {
                0: "No action needed. All Elastic IPs are properly associated with running instances.",
                1: "Review unassociated Elastic IPs and release if not needed to avoid unnecessary charges.",
                2: "Release unused Elastic IP allocations immediately to \nprevent potential security risks and costs.",
                3: "Investigate why Elastic IP status could not be determined.",
                4: "Elastic IP data incomplete - unable to verify usage status."
            },
            'instance_profile': {
                0: "No action needed. Instance has proper IAM instance profile attached.",
                2: "Attach IAM instance profile to EC2 instance. Avoid \nembedding access keys in code or configuration.",
                3: "Investigate why IAM instance profile status could not be retrieved.",
                4: "Instance profile data incomplete - unable to verify IAM role attachment."
            },
            'role_wildcard_permissions': {
                0: "No action needed. IAM roles follow principle of least \nprivilege without wildcard permissions.",
                1: "Review IAM role policies with wildcards. Consider whether \nbroad permissions are necessary.",
                2: "Remove wildcard (*) permissions from IAM role policies. \nGrant only specific permissions required.",
                3: "Investigate why IAM role policy documents could not be retrieved or parsed.",
                4: "IAM role policy data incomplete - unable to verify permissions."
            },
            'unused_iam_role': {
                0: "No action needed. IAM role is actively used by EC2 instances.",
                1: "Review unused IAM role and consider deletion if no longer needed.",
                2: "Delete or repurpose unused IAM role to reduce attack surface.",
                3: "Investigate why IAM role usage could not be determined.",
                4: "IAM role usage data incomplete - unable to verify role attachment."
            },
            'ebs_encryption': {
                0: "No action needed. All EBS volumes are encrypted.",
                2: "Enable encryption for EBS volumes. Consider enabling \ndefault EBS encryption for the account.",
                3: "Investigate why EBS volume encryption status could not be retrieved.",
                4: "EBS volume data incomplete - unable to verify encryption status."
            },
            'ami_public': {
                0: "No action needed. Instance uses private or approved AMI.",
                1: "Review use of public AMI. Ensure it's from a trusted \nsource and meets security requirements.",
                2: "Replace public or unapproved AMI with organization-approved private AMI.",
                3: "Investigate why AMI information could not be retrieved.",
                4: "AMI data incomplete - unable to verify AMI source."
            },
            'snapshot_security': {
                0: "No action needed. EBS snapshots are encrypted and not publicly accessible.",
                1: "Review snapshot permissions and consider additional access restrictions.",
                2: "Encrypt snapshots and remove public access permissions immediately.",
                3: "Investigate why snapshot security status could not be retrieved.",
                4: "Snapshot data incomplete - unable to verify encryption and access permissions."
            },
            'cloudtrail_logging': {
                0: "No action needed. CloudTrail is properly configured for\n EC2 API logging across all regions.",
                2: "Enable CloudTrail with multi-region support and configure\nlog delivery to S3 for EC2 API monitoring.",
                3: "Investigate why CloudTrail configuration could not be retrieved.",
                4: "CloudTrail data incomplete - unable to verify logging configuration."
            },
            'vpc_flow_logs': {
                0: "No action needed. VPC Flow Logs are enabled for network monitoring.",
                2: "Enable VPC Flow Logs for all VPCs to monitor network \ntraffic and detect anomalies.",
                3: "Investigate why VPC Flow Logs status could not be retrieved.",
                4: "VPC Flow Logs data incomplete - unable to verify logging status."
            },
            'detailed_monitoring': {
                0: "No action needed. CloudWatch detailed monitoring is enabled.",
                1: "Consider enabling CloudWatch detailed monitoring for \nbetter visibility into instance performance.",
                2: "Enable CloudWatch detailed monitoring and install CloudWatch \nagent for comprehensive monitoring.",
                3: "Investigate why monitoring status could not be retrieved.",
                4: "Monitoring data incomplete - unable to verify CloudWatch configuration."
            },
            'ami_age': {
                0: "No action needed. AMI is recent or from supported long-term \nsupport version.",
                1: "Review AMI age and plan for updates. Consider using more recent AMI versions.",
                2: "Update to newer AMI version. Launch new instances with \ncurrent AMI and migrate workloads.",
                3: "Investigate why AMI creation date could not be retrieved.",
                4: "AMI age data incomplete - unable to verify AMI currency."
            },
            'ssm_managed': {
                0: "No action needed. Instance is managed by AWS Systems \nManager for automated patching.",
                2: "Install and configure SSM agent for automated patch \nmanagement and compliance monitoring.",
                3: "Investigate why SSM management status could not be retrieved.",
                4: "SSM data incomplete - unable to verify instance management status."
            },
            'keypair_rotation': {
                0: "No action needed. SSH key pairs are regularly rotated.",
                1: "Plan key pair rotation as keys are approaching recommended rotation period.",
                2: "Rotate SSH key pairs that are older than 180 days for better security hygiene.",
                3: "Investigate why key pair creation dates could not be retrieved.",
                4: "Key pair data incomplete - unable to verify rotation status."
            },
            'instance_lifecycle': {
                0: "No action needed. Instance is actively running in approved regions.",
                1: "Review stopped instances and determine if they should be terminated or restarted.",
                2: "Terminate or restart unused instances. Move instances from unapproved regions.",
                3: "Investigate why instance state or region information could not be retrieved.",
                4: "Instance lifecycle data incomplete - unable to verify state and location."
            },
            'default_security_group': {
                0: "No action needed. Default security group properly restricts all traffic.",
                2: "Remove all rules from default security group to\n follow CIS benchmark recommendations.",
                3: "Investigate why default security group configuration could not be retrieved.",
                4: "Default security group data incomplete - unable to verify rule configuration."
            },
            'imdsv2_enforcement': {
                0: "No action needed. Instance Metadata Service v2 (IMDSv2) is enforced.",
                2: "Enable IMDSv2 enforcement to protect against SSRF\n attacks on instance metadata.",
                3: "Investigate why IMDS configuration could not be retrieved.",
                4: "IMDS data incomplete - unable to verify metadata service configuration."
            },
            'nitro_enclave': {
                0: "No action needed. Sensitive workloads are using \nNitro Enclaves where appropriate.",
                1: "Consider using Nitro Enclaves for highly sensitive \nworkloads requiring additional isolation.",
                3: "Investigate why Nitro Enclave status could not be determined.",
                4: "Nitro Enclave data incomplete - unable to verify enclave usage."
            }
        }

    def add_result(self, category, check_type, status, description, region, resource):
        """Add result with proper status mapping and remediation"""
        self.results.append({
            "Category": category,
            "Check": check_type,
            "Description": description,
            "Resource": resource,
            "Region": region,
            "Status": ["PASS", "WARN", "FAIL", "ERROR", "INCOMPLETE"][status],
            "Remediation": self.remediation_map[check_type][status]
        })

    def default_region(self, settings):
        return settings.get("region", "ap-south-1")

    def default_partition(self, settings):
        return settings.get("partition", "aws")

    def check_public_access_controls(self, inst, region, partition):
        """CIS Control: Check public IP and security group configurations"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        # Check public IP assignment
        if inst.get("PublicIp"):
            # Could be justified for specific use cases, so WARN rather than FAIL
            self.add_result("EC2", "public_ip", 1, 
                          f"Instance {instance_id} has public IP assigned", 
                          region, resource)
        else:
            self.add_result("EC2", "public_ip", 0, 
                          f"Instance {instance_id} has no public IP", 
                          region, resource)

        # Check security groups for open SSH/RDP
        sg_open_ssh_rdp = False
        sg_open_all = False
        
        try:
            for sg in inst.get("SecurityGroups", []):
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp")
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        
                        if cidr == "0.0.0.0/0":
                            # Check for SSH/RDP access
                            if from_port in [22, 3389] or (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                                sg_open_ssh_rdp = True
                            
                            # Check for all ports open
                            if from_port == 0 and to_port == 65535:
                                sg_open_all = True

            self.add_result("EC2", "sg_open_ssh_rdp", 
                          2 if sg_open_ssh_rdp else 0,
                          f"Security group allows SSH/RDP from internet" if sg_open_ssh_rdp else f"SSH/RDP access properly restricted",
                          region, resource)

            self.add_result("EC2", "sg_open_all_ports", 
                          2 if sg_open_all else 0,
                          f"Security group allows all ports from internet" if sg_open_all else f"Port access properly restricted",
                          region, resource)

        except Exception as e:
            self.add_result("EC2", "sg_open_ssh_rdp", 3, 
                          f"Error checking security group rules: {str(e)}", 
                          region, resource)

    def check_default_security_group(self, vpc_data, region, partition):
        """CIS Control: Ensure default security group restricts all traffic"""
        for vpc_id, sg_data in vpc_data.items():
            resource = f"arn:{partition}:ec2:{region}::security-group/{sg_data.get('GroupId', 'unknown')}"
            
            try:
                has_rules = (len(sg_data.get("IpPermissions", [])) > 0 or 
                           len(sg_data.get("IpPermissionsEgress", [])) > 1)  # Default egress rule allowed
                
                self.add_result("EC2", "default_security_group", 
                              2 if has_rules else 0,
                              f"Default security group has active rules" if has_rules else f"Default security group properly configured",
                              region, resource)
            except Exception as e:
                self.add_result("EC2", "default_security_group", 3, 
                              f"Error checking default security group: {str(e)}", 
                              region, resource)

    def check_elastic_ip_usage(self, inst, region, partition):
        """Check for unused Elastic IP allocations"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        try:
            eip_allocation = inst.get("ElasticIpAllocation")
            public_ip = inst.get("PublicIp")
            
            if eip_allocation and not public_ip:
                self.add_result("EC2", "elastic_ip_unused", 2, 
                              f"Unused Elastic IP allocation: {eip_allocation}", 
                              region, resource)
            else:
                self.add_result("EC2", "elastic_ip_unused", 0, 
                              f"No unused Elastic IP allocations", 
                              region, resource)
        except Exception as e:
            self.add_result("EC2", "elastic_ip_unused", 3, 
                          f"Error checking Elastic IP usage: {str(e)}", 
                          region, resource)

    def check_iam_configurations(self, inst, role_docs, unused_roles, region, partition):
        """Check IAM instance profiles and role permissions"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        try:
            roles = inst.get("IamRoles", [])
            
            # Check instance profile attachment
            if not roles:
                self.add_result("EC2", "instance_profile", 2, 
                              f"Instance {instance_id} missing IAM instance profile", 
                              region, resource)
                return
            
            self.add_result("EC2", "instance_profile", 0, 
                          f"Instance {instance_id} has IAM instance profile", 
                          region, resource)

            # Check role permissions for wildcards
            for role_name in roles:
                role_resource = f"arn:{partition}:iam::{role_name}"
                docs = role_docs.get(role_name, {})
                has_wildcards = False
                
                # Check inline policies
                for policy_doc in docs.get("Inline", {}).values():
                    if self._has_wildcard_permissions(policy_doc):
                        has_wildcards = True
                        break
                
                # Check managed policies
                if not has_wildcards:
                    for policy_doc in docs.get("Managed", {}).values():
                        if self._has_wildcard_permissions(policy_doc):
                            has_wildcards = True
                            break

                self.add_result("EC2", "role_wildcard_permissions", 
                              2 if has_wildcards else 0,
                              f"Role {role_name} has wildcard permissions" if has_wildcards else f"Role {role_name} follows least privilege",
                              region, role_resource)
                
                # Mark role as used
                if role_name in unused_roles:
                    unused_roles.remove(role_name)

        except Exception as e:
            self.add_result("EC2", "instance_profile", 3, 
                          f"Error checking IAM configuration: {str(e)}", 
                          region, resource)

    def _has_wildcard_permissions(self, policy_doc):
        """Check if policy document contains wildcard permissions"""
        try:
            policy_str = json.dumps(policy_doc)
            return "*" in policy_str
        except:
            return False

    def check_storage_security(self, inst, volumes, amis, snapshots_by_vol, region, partition):
        """Check EBS encryption, AMI security, and snapshot configurations"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        try:
            # Check EBS volume encryption
            for volume_id in inst.get("Volumes", []):
                vol_resource = f"arn:{partition}:ec2:{region}::volume/{volume_id}"
                volume = volumes.get(volume_id, {})
                encrypted = volume.get("Encrypted", False)
                
                self.add_result("EC2", "ebs_encryption", 
                              0 if encrypted else 2,
                              f"EBS volume {volume_id} encrypted" if encrypted else f"EBS volume {volume_id} not encrypted",
                              region, vol_resource)

            # Check AMI security
            ami_id = inst.get("ImageId")
            if ami_id:
                ami = amis.get(ami_id, {})
                is_public = ami.get("Public", False)
                
                self.add_result("EC2", "ami_public", 
                              2 if is_public else 0,
                              f"Instance using public AMI {ami_id}" if is_public else f"Instance using private/approved AMI",
                              region, resource)

            # Check snapshot security
            for volume_id in inst.get("Volumes", []):
                for snapshot in snapshots_by_vol.get(volume_id, []):
                    snap_id = snapshot.get("SnapshotId", "unknown")
                    snap_resource = f"arn:{partition}:ec2:{region}::snapshot/{snap_id}"
                    encrypted = snapshot.get("Encrypted", False)
                    public = snapshot.get("Public", False)
                    
                    secure = encrypted and not public
                    self.add_result("EC2", "snapshot_security", 
                                  0 if secure else 2,
                                  f"Snapshot {snap_id} secure" if secure else f"Snapshot {snap_id} insecure",
                                  region, snap_resource)

        except Exception as e:
            self.add_result("EC2", "ebs_encryption", 3, 
                          f"Error checking storage security: {str(e)}", 
                          region, resource)

    def check_monitoring_logging(self, inst, trails, flow_logs_map, region, partition):
        """Check CloudTrail logging and VPC Flow Logs"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        try:
            # Check detailed monitoring
            detailed_monitoring = inst.get("Monitoring") == "enabled"
            self.add_result("EC2", "detailed_monitoring", 
                          0 if detailed_monitoring else 1,
                          f"CloudWatch detailed monitoring enabled" if detailed_monitoring else f"CloudWatch detailed monitoring disabled",
                          region, resource)

            # Check VPC Flow Logs
            vpc_id = inst.get("VpcId")
            if vpc_id:
                flow_logs_enabled = flow_logs_map.get(vpc_id, False)
                vpc_resource = f"arn:{partition}:ec2:{region}::vpc/{vpc_id}"
                
                self.add_result("EC2", "vpc_flow_logs", 
                              0 if flow_logs_enabled else 2,
                              f"VPC Flow Logs enabled for {vpc_id}" if flow_logs_enabled else f"VPC Flow Logs disabled for {vpc_id}",
                              region, vpc_resource)

        except Exception as e:
            self.add_result("EC2", "detailed_monitoring", 3, 
                          f"Error checking monitoring configuration: {str(e)}", 
                          region, resource)

    def check_patch_management(self, inst, amis, ssm_managed, region, partition):
        """Check AMI age and SSM management"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        try:
            # Check AMI age
            ami_id = inst.get("ImageId")
            if ami_id:
                ami = amis.get(ami_id, {})
                creation_date = ami.get("CreationDate")
                
                if creation_date:
                    try:
                        created_date = datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                        age_days = (datetime.utcnow() - created_date).days
                        outdated = age_days > 365
                        
                        self.add_result("EC2", "ami_age", 
                                      2 if outdated else 0,
                                      f"AMI {ami_id} is {age_days} days old" if outdated else f"AMI {ami_id} is current",
                                      region, resource)
                    except ValueError:
                        self.add_result("EC2", "ami_age", 3, 
                                      f"Could not parse AMI creation date: {creation_date}", 
                                      region, resource)

            # Check SSM management
            ssm_managed_instance = instance_id in ssm_managed
            self.add_result("EC2", "ssm_managed", 
                          0 if ssm_managed_instance else 2,
                          f"Instance managed by SSM" if ssm_managed_instance else f"Instance not managed by SSM",
                          region, resource)

        except Exception as e:
            self.add_result("EC2", "ami_age", 3, 
                          f"Error checking patch management: {str(e)}", 
                          region, resource)

    def check_keypair_rotation(self, key_pairs, region, partition):
        """Check SSH key pair rotation"""
        try:
            threshold_date = datetime.utcnow() - timedelta(days=180)
            
            for keypair in key_pairs:
                key_name = keypair.get("KeyName", "unknown")
                resource = f"arn:{partition}:ec2:{region}::key-pair/{key_name}"
                create_time = keypair.get("CreateTime")
                
                if create_time:
                    stale = create_time.replace(tzinfo=None) < threshold_date
                    self.add_result("EC2", "keypair_rotation", 
                                  2 if stale else 0,
                                  f"Key pair {key_name} is stale (>180 days)" if stale else f"Key pair {key_name} is current",
                                  region, resource)
                else:
                    self.add_result("EC2", "keypair_rotation", 4, 
                                  f"Key pair {key_name} missing creation time", 
                                  region, resource)

        except Exception as e:
            self.add_result("EC2", "keypair_rotation", 3, 
                          f"Error checking key pair rotation: {str(e)}", 
                          region, resource)

    def check_instance_lifecycle(self, inst, allowed_regions, region, partition):
        """Check instance state and region compliance"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        try:
            # Check instance state
            state = inst.get("State", "unknown")
            instance_region = inst.get("Region", region)
            
            if state == "stopped":
                self.add_result("EC2", "instance_lifecycle", 1, 
                              f"Instance {instance_id} is stopped", 
                              region, resource)
            elif instance_region not in allowed_regions:
                self.add_result("EC2", "instance_lifecycle", 2, 
                              f"Instance {instance_id} in unapproved region {instance_region}", 
                              region, resource)
            else:
                self.add_result("EC2", "instance_lifecycle", 0, 
                              f"Instance {instance_id} is running in approved region", 
                              region, resource)

        except Exception as e:
            self.add_result("EC2", "instance_lifecycle", 3, 
                          f"Error checking instance lifecycle: {str(e)}", 
                          region, resource)

    def check_metadata_service(self, inst, region, partition):
        """Check Instance Metadata Service v2 enforcement"""
        instance_id = inst.get("InstanceId", "unknown")
        resource = f"arn:{partition}:ec2:{region}::{instance_id}"
        
        try:
            # Check if IMDSv2 is enforced
            metadata_options = inst.get("MetadataOptions", {})
            imdsv2_required = metadata_options.get("HttpTokens") == "required"
            
            self.add_result("EC2", "imdsv2_enforcement", 
                          0 if imdsv2_required else 2,
                          f"IMDSv2 enforced for {instance_id}" if imdsv2_required else f"IMDSv2 not enforced for {instance_id}",
                          region, resource)

        except Exception as e:
            self.add_result("EC2", "imdsv2_enforcement", 3, 
                          f"Error checking metadata service configuration: {str(e)}", 
                          region, resource)

    def run(self, cache, settings, callback):
        """Main execution method following the established methodology"""
        try:
            self.results = []
            partition = self.default_partition(settings)
            region = self.default_region(settings)
            
            # Extract data from cache
            data = cache.get('ec2', {})
            instances = data.get("Instances", [])
            volumes = data.get("Volumes", {})
            amis = data.get("AMIs", {})
            snapshots = data.get("Snapshots", [])
            trails = data.get("Trails", [])
            flow_logs = data.get("FlowLogs", [])
            ssm_managed = data.get("SSMManaged", [])
            role_docs = data.get("RolePolicyDocs", {})
            key_pairs = data.get("KeyPairs", [])
            default_sgs = data.get("DefaultSecurityGroups", {})
            
            # Settings
            allowed_regions = settings.get("allowed_regions", [region])
            
            # Process snapshots by volume
            snapshots_by_vol = defaultdict(list)
            for snapshot in snapshots:
                volume_id = snapshot.get("VolumeId")
                if volume_id:
                    snapshots_by_vol[volume_id].append(snapshot)

            # Create flow logs mapping
            flow_logs_map = {fl.get("ResourceId"): True for fl in flow_logs}

            # Check CloudTrail (account-wide check)
            if trails:
                self.add_result("EC2", "cloudtrail_logging", 0, 
                              "CloudTrail enabled for account", 
                              region, f"arn:{partition}:cloudtrail:{region}::trail")
            else:
                self.add_result("EC2", "cloudtrail_logging", 2, 
                              "CloudTrail not configured", 
                              region, f"arn:{partition}:cloudtrail:{region}::trail")

            # Track unused roles
            unused_roles = set(data.get("AllRoles", []))

            # Process each instance
            for instance in instances:
                inst_region = instance.get("Region", region)
                
                self.check_public_access_controls(instance, inst_region, partition)
                self.check_elastic_ip_usage(instance, inst_region, partition)
                self.check_iam_configurations(instance, role_docs, unused_roles, inst_region, partition)
                self.check_storage_security(instance, volumes, amis, snapshots_by_vol, inst_region, partition)
                self.check_monitoring_logging(instance, trails, flow_logs_map, inst_region, partition)
                self.check_patch_management(instance, amis, ssm_managed, inst_region, partition)
                self.check_instance_lifecycle(instance, allowed_regions, inst_region, partition)
                self.check_metadata_service(instance, inst_region, partition)

            # Check unused IAM roles
            for role_name in unused_roles:
                role_resource = f"arn:{partition}:iam::{role_name}"
                self.add_result("EC2", "unused_iam_role", 2, 
                              f"IAM role {role_name} not attached to any EC2 instance", 
                              region, role_resource)

            # Check key pair rotation
            self.check_keypair_rotation(key_pairs, region, partition)

            # Check default security groups
            self.check_default_security_group(default_sgs, region, partition)

            # Return results via callback
            callback(None, self.results, {})

        except Exception as e:
            callback(str(e), [], {})