# ec2_policy.py

from datetime import datetime, timedelta
import json
from collections import defaultdict

class EC2MisconfigChecker:
    def __init__(self):
        self.results = []
        self.remediation = {
            'public_ip': {
                0: "No public IP (or justified).",
                1: "Remove unnecessary public IP or use private subnet."
            },
            'sg_open': {
                0: "No insecure 0.0.0.0/0 ingress on 22/3389.",
                1: "Restrict SG ingress; use bastion / VPN."
            },
            'elastic_ip': {
                0: "No unused Elastic IP.",
                1: "Release Elastic IP if not required."
            },
            'instance_profile': {
                0: "Instance has IAM role.",
                1: "Attach IAM instance profile; avoid embedded creds."
            },
            'role_wildcard': {
                0: "Role least-privileged (no * wildcards).",
                1: "Remove wildcard Action/Resource from role policies."
            },
            'unused_role': {
                0: "Role attached to at least one EC2.",
                1: "Delete or repurpose unused IAM role."
            },
            'ebs_encrypt': {
                0: "All EBS volumes encrypted.",
                1: "Encrypt EBS volume or enable default encryption."
            },
            'ami_public': {
                0: "AMI is private or approved.",
                1: "Replace public / unapproved AMI."
            },
            'snapshot_encrypt': {
                0: "Snapshot encrypted & private.",
                1: "Encrypt or restrict snapshot."
            },
            'cloudtrail': {
                0: "CloudTrail logging EC2 API in all regions.",
                1: "Enable multi-region CloudTrail with logs in S3."
            },
            'flowlogs': {
                0: "VPC Flow Logs enabled.",
                1: "Enable VPC Flow Logs for all VPCs."
            },
            'detailed_monitor': {
                0: "Detailed monitoring enabled.",
                1: "Enable CloudWatch detailed monitoring / agent."
            },
            'outdated_ami': {
                0: "AMI recent or LTS supported.",
                1: "Re-launch EC2 with supported AMI."
            },
            'ssm_managed': {
                0: "SSM agent present.",
                1: "Install/repair SSM agent for patch automation."
            },
            'stale_keypair': {
                0: "Key pair rotated recently.",
                1: "Rotate or remove stale key pair."
            },
            'unused_instance': {
                0: "Instance in use.",
                1: "Stop/terminate unused instance."
            },
        }

    def add(self, check, status, desc, resource=''):
        self.results.append({
            "Check": check,
            "Status": ['PASS', 'FAIL'][status],
            "Description": desc,
            "Resource": resource,
            "Remediation": self.remediation[check][status]
        })

    def check_public_and_sg(self, inst):
        if inst.get("PublicIp"):
            self.add('public_ip', 1, "Public IP attached", inst["InstanceId"])
        else:
            self.add('public_ip', 0, "Private-only", inst["InstanceId"])

        sg_open = False
        for sg in inst.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                for rng in rule.get("IpRanges", []):
                    cidr = rng.get("CidrIp")
                    port = rule.get("FromPort")
                    if cidr == "0.0.0.0/0" and port in [22, 3389]:
                        sg_open = True
        self.add('sg_open', 1 if sg_open else 0,
                 "0.0.0.0/0 on 22/3389" if sg_open else "Ingress restricted", inst["InstanceId"])

        if inst.get("ElasticIpAllocation") and not inst.get("PublicIp"):
            self.add('elastic_ip', 1, "Allocated EIP not in use", inst["ElasticIpAllocation"])
        else:
            self.add('elastic_ip', 0, "No unused EIP", inst["InstanceId"])

    def check_role(self, inst, role_docs, unused_roles):
        roles = inst.get("IamRoles", [])
        if not roles:
            self.add('instance_profile', 1, "Missing IAM role", inst["InstanceId"])
            return
        self.add('instance_profile', 0, "Has instance profile", inst["InstanceId"])

        for rn in roles:
            docs = role_docs.get(rn, {})
            hit = False
            for doc in docs.get("Inline", {}).values():
                if "*" in json.dumps(doc.get("Statement", {})):
                    hit = True
            for doc in docs.get("Managed", {}).values():
                if "*" in json.dumps(doc.get("Statement", {})):
                    hit = True
            self.add('role_wildcard', 1 if hit else 0,
                     "Wildcard perms in role" if hit else "Least privilege", rn)

        for rn in roles:
            if rn in unused_roles:
                unused_roles.remove(rn)

    def check_storage(self, inst, vols, amis, snapshots_by_vol):
        for vid in inst.get("Volumes", []):
            enc = vols.get(vid, {}).get("Encrypted")
            self.add('ebs_encrypt', 0 if enc else 1,
                     "Encrypted" if enc else "Unencrypted", vid)

        aid = inst.get("ImageId")
        ami = amis.get(aid, {})
        if ami.get("Public"):
            self.add('ami_public', 1, f"Public AMI {aid}", inst["InstanceId"])
        else:
            self.add('ami_public', 0, "AMI private/approved", inst["InstanceId"])

        for vid in inst.get("Volumes", []):
            for snap in snapshots_by_vol.get(vid, []):
                enc = snap.get("Encrypted", False)
                pub = snap.get("Public", False)
                status = 0 if enc and not pub else 1
                self.add('snapshot_encrypt', status,
                         "Snapshot ok" if status == 0 else "Unencrypted or public snapshot",
                         snap.get("SnapshotId"))

    def check_monitoring(self, inst, trails, flow_logs_map):
        vpc = inst.get("VpcId")
        fl_en = flow_logs_map.get(vpc, False)
        self.add('flowlogs', 0 if fl_en else 1,
                 "Flow logs ON" if fl_en else "Flow logs OFF", vpc)

        detailed = inst.get("Monitoring") == "enabled"
        self.add('detailed_monitor', 0 if detailed else 1,
                 "Detailed monitoring" if detailed else "Basic monitoring", inst["InstanceId"])

    def check_patch(self, inst, amis, ssm_managed):
        aid = inst.get("ImageId")
        ami = amis.get(aid, {})
        outdated = False
        try:
            cdate = datetime.strptime(ami.get("CreationDate", "1970-01-01"), "%Y-%m-%dT%H:%M:%S.%fZ")
            if cdate < datetime.utcnow() - timedelta(days=365):
                outdated = True
        except Exception:
            pass
        self.add('outdated_ami', 1 if outdated else 0,
                 "AMI >1yr old" if outdated else "AMI recent", inst["InstanceId"])

        in_ssm = inst.get("InstanceId") in ssm_managed
        self.add('ssm_managed', 0 if in_ssm else 1,
                 "SSM managed" if in_ssm else "Not in SSM", inst["InstanceId"])

    def check_keypair(self, key_pairs):
        threshold = datetime.utcnow() - timedelta(days=180)
        for kp in key_pairs:
            ctime = kp.get("CreateTime")
            if not ctime:
                continue
            stale = ctime.replace(tzinfo=None) < threshold
            self.add('stale_keypair', 1 if stale else 0,
                     "Key >180d" if stale else "Key fresh", kp["KeyName"])

    def check_lifecycle(self, inst, allowed_regions):
        stopped = inst.get("State") == "stopped"
        self.add('unused_instance', 1 if stopped else 0,
                 "Stopped instance" if stopped else "Running", inst["InstanceId"])

        if inst.get("Region") not in allowed_regions:
            self.add('unused_instance', 1,
                     f"Instance in disallowed region {inst['Region']}", inst["InstanceId"])

    def run(self, cache, settings, callback):
        try:
            data   = cache.get('ec2', {})
            insts  = data.get("Instances", [])
            vols   = data.get("Volumes", {})
            amis   = data.get("AMIs", {})
            snaps  = data.get("Snapshots", [])
            trails = data.get("Trails", [])
            flow   = data.get("FlowLogs", [])
            ssm_m  = data.get("SSMManaged", [])
            role_docs = data.get("RolePolicyDocs", {})
            key_pairs = data.get("KeyPairs", [])
            allowed_regions = settings.get("allowed_regions", [settings["region"]])

            snapshots_by_vol = defaultdict(list)
            for s in snaps:
                if s.get("VolumeId"):
                    snapshots_by_vol[s["VolumeId"]].append(s)

            flow_map = {f.get("ResourceId"): True for f in flow}

            if trails:
                self.add('cloudtrail', 0, "CloudTrail enabled account-wide")
            else:
                self.add('cloudtrail', 1, "No CloudTrail found")

            unused_roles = set(data.get("AllRoles", []))

            for inst in insts:
                self.check_public_and_sg(inst)
                self.check_role(inst, role_docs, unused_roles)
                self.check_storage(inst, vols, amis, snapshots_by_vol)
                self.check_monitoring(inst, trails, flow_map)
                self.check_patch(inst, amis, ssm_m)
                self.check_lifecycle(inst, allowed_regions)

            for rn in unused_roles:
                self.add('unused_role', 1, "Role not attached to EC2", rn)

            self.check_keypair(key_pairs)

            callback(None, self.results, {})
        except Exception as e:
            callback(str(e), [], {})
