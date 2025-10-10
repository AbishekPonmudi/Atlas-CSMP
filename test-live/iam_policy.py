# ec2_policy.py  – enhanced PASS/WARN/FAIL/ERROR version
from datetime import datetime, timedelta
from collections import defaultdict
import json

STATUS_STR = ['PASS', 'WARN', 'FAIL', 'ERROR']

class EC2MisconfigChecker:
    """
    Evaluates EC2 posture for:
      • Public exposure, IAM roles, storage encryption, logging/monitoring,
        patch baseline, SSH keys, lifecycle, and more.
    Produces results with Status ∈ {PASS, WARN, FAIL, ERROR}.
    """

    def __init__(self):
        self.results = []

        # Remediation catalogue (indexed by status)
        self.remediation = {
            'public_ip': {
                0: "No action needed – instance is not directly reachable from the Internet.",
                1: "Review business justification for public IP; if required, place behind an ELB or bastion tier.",
                2: "Remove the public IPv4 address or move instance to a private subnet.",
                3: "Could not evaluate public-IP status – check permissions and retry."
            },
            'sg_open': {
                0: "No action needed – remote admin ports are restricted.",
                1: "Restrict SSH/RDP to a limited CIDR, VPN or bastion host.",
                2: "Remove 0.0.0.0/0 rule on port 22/3389 immediately; violates CIS §2.1.1.",
                3: "Security-group lookup failed – verify IAM permissions."
            },
            'elastic_ip': {
                0: "All allocated Elastic IPs are in use.",
                1: "Release or associate the orphaned Elastic IP to avoid cost/leakage.",
                2: "N/A",
                3: "Could not enumerate EIPs."
            },
            'instance_profile': {
                0: "Instance uses an IAM role (best practice).",
                1: "Migrate credentials into an IAM instance profile; delete embedded secrets.",
                2: "Critical: instance has *no* IAM role and likely uses long-lived keys.",
                3: "Error while checking instance profile – investigate permissions."
            },
            'role_wildcard': {
                0: "Role follows least-privilege.",
                1: "Review and narrow permissions; avoid * in Action/Resource.",
                2: "Remove wildcard (*) permissions - violates CIS §2.1.5 and NIST AC-6.",
                3: "Could not parse role policy documents."
            },
            'unused_role': {
                0: "Role is currently attached to at least one instance.",
                1: "Delete or repurpose unused role; reduces attack surface.",
                2: "N/A",
                3: "Role enumeration failed."
            },
            'ebs_encrypt': {
                0: "EBS volume is encrypted at rest.",
                1: "Enable default EBS encryption and re-create volume.",
                2: "Encrypt the volume or copy to an encrypted snapshot – CIS §2.3.1.",
                3: "Volume encryption state unknown."
            },
            'ami_public': {
                0: "AMI is private or comes from an approved publisher.",
                1: "Verify AMI origin; prefer organisational golden AMIs.",
                2: "Replace the public/unverified AMI – potential supply-chain risk.",
                3: "AMI details could not be obtained."
            },
            'snapshot_encrypt': {
                0: "Snapshot is encrypted & not shared publicly.",
                1: "Re-copy snapshot with encryption or restrict permissions.",
                2: "Snapshot is public and/or unencrypted – encrypt & limit access.",
                3: "Could not evaluate snapshot."
            },
            'cloudtrail': {
                0: "CloudTrail is capturing EC2 API calls.",
                1: "Enable a multi-region CloudTrail trail with log file validation.",
                2: "No CloudTrail– EC2 activity not auditable (CIS §2.6).",
                3: "CloudTrail enumeration failed."
            },
            'flowlogs': {
                0: "VPC Flow Logs are enabled for this VPC.",
                1: "Enable Flow Logs (ALL traffic, 1-minute) to meet NIST IR-4.",
                2: "N/A",
                3: "Flow-log status unknown."
            },
            'detailed_monitor': {
                0: "Detailed monitoring (1-min) is enabled.",
                1: "Enable detailed monitoring or install CloudWatch agent.",
                2: "N/A",
                3: "Unable to verify monitoring state."
            },
            'outdated_ami': {
                0: "AMI is within support window.",
                1: "Plan re-bake/redeploy instance with current patched AMI.",
                2: "Instance runs an end-of-life OS – rebuild immediately.",
                3: "Could not parse AMI creation date."
            },
            'ssm_managed': {
                0: "Instance is registered with AWS Systems Manager.",
                1: "Install/repair SSM agent or attach IAM `AmazonSSMManagedInstanceCore`.",
                2: "N/A",
                3: "SSM fleet enumeration failed."
            },
            'stale_keypair': {
                0: "Key pair rotated within 180 days.",
                1: "Regenerate key pair and update instance.",
                2: "Key pair appears compromised – rotate immediately.",
                3: "Key-pair metadata not available."
            },
            'unused_instance': {
                0: "Instance is active or in an allowed region.",
                1: "Stop/terminate instance to save cost or move to approved region.",
                2: "Running in disallowed region – violates governance.",
                3: "Could not read instance lifecycle state."
            },
        }

    # --------------------- helper ---------------------------------- #
    def _add(self, check, status, desc, resource=''):
        self.results.append({
            "Check": check,
            "Status": STATUS_STR[status],
            "Description": desc,
            "Resource": resource,
            "Remediation": self.remediation[check][status]
        })

    # --------------------- individual check helpers ---------------- #
    def _check_public_and_sg(self, inst):
        iid = inst["InstanceId"]

        # region A – public IP
        if inst.get("PublicIp"):
            self._add('public_ip', 2, "Instance has a public IPv4 address", iid)
        else:
            self._add('public_ip', 0, "Instance has no public IP", iid)

        # region B – wide-open SG
        wide_open = False
        harmless  = True
        for sg in inst.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                cidrs = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                if "0.0.0.0/0" in cidrs:
                    harmless = False
                    if rule.get("FromPort") in [22, 3389]:
                        wide_open = True
        if wide_open:
            self._add('sg_open', 2, "SSH/RDP exposed to world", iid)
        elif not harmless:
            self._add('sg_open', 1, "Wide-open ingress on non-admin port", iid)
        else:
            self._add('sg_open', 0, "Ingress rules are restricted", iid)

        # region C – orphaned Elastic IP
        if inst.get("ElasticIpAllocation") and not inst.get("PublicIp"):
            self._add('elastic_ip', 1, "Elastic IP allocated but not associated", inst['ElasticIpAllocation'])
        else:
            self._add('elastic_ip', 0, "No dangling Elastic IP", iid)

    def _check_role(self, inst, role_docs, unused_roles):
        iid = inst["InstanceId"]
        roles = inst.get("IamRoles", [])

        if not roles:
            self._add('instance_profile', 2, "No IAM instance profile attached", iid)
            return
        self._add('instance_profile', 0, "IAM role attached", iid)

        for rn in roles:
            docs = role_docs.get(rn, {})
            if docs == {}:
                self._add('role_wildcard', 3, "Could not retrieve policy doc", rn)
                continue
            wildcard = False
            for doc in list(docs.get("Inline", {}).values()) + list(docs.get("Managed", {}).values()):
                if "*" in json.dumps(doc.get("Statement", {})):
                    wildcard = True
            self._add('role_wildcard', 2 if wildcard else 0,
                      "Wildcard found in role" if wildcard else "No wildcard permissions", rn)

        for rn in roles:
            unused_roles.discard(rn)

    def _check_storage(self, inst, vols, amis, snap_by_vol):
        iid = inst["InstanceId"]

        # ----- EBS
        for vid in inst.get("Volumes", []):
            enc = vols.get(vid, {}).get("Encrypted")
            self._add('ebs_encrypt', 2 if enc is False else 0,
                      "Volume not encrypted" if enc is False else "Encrypted", vid)

            # snapshots of that volume
            for snap in snap_by_vol.get(vid, []):
                enc_s = snap.get("Encrypted", False)
                pub   = snap.get("Public", False)
                if not enc_s or pub:
                    self._add('snapshot_encrypt', 2, "Snapshot unencrypted or public", snap["SnapshotId"])
                else:
                    self._add('snapshot_encrypt', 0, "Snapshot protected", snap["SnapshotId"])

        # ----- AMI
        aid = inst.get("ImageId")
        ami = amis.get(aid, {})
        if ami == {}:
            self._add('ami_public', 3, "AMI metadata unavailable", aid)
        elif ami.get("Public"):
            self._add('ami_public', 2, "Instance based on a *public* AMI", iid)
        else:
            self._add('ami_public', 0, "AMI is private/approved", iid)

    def _check_monitoring(self, inst, flow_map):
        iid = inst["InstanceId"]
        vpc = inst.get("VpcId")

        # Flow Logs
        if vpc is None:
            self._add('flowlogs', 3, "Instance has no VPC? – cannot evaluate", iid)
        elif flow_map.get(vpc):
            self._add('flowlogs', 0, "Flow Logs enabled for VPC", vpc)
        else:
            self._add('flowlogs', 1, "Flow Logs disabled for VPC", vpc)

        # Detailed monitoring
        detailed = inst.get("Monitoring") == "enabled"
        self._add('detailed_monitor', 0 if detailed else 1,
                  "1-minute metrics enabled" if detailed else "Using 5-minute basic metrics", iid)

    def _check_patch(self, inst, amis, ssm_managed):
        iid = inst["InstanceId"]
        aid = inst.get("ImageId")
        ami = amis.get(aid, {})

        # AMI freshness
        try:
            created = datetime.strptime(ami.get("CreationDate", "1970-01-01"), "%Y-%m-%dT%H:%M:%S.%fZ")
            days_old = (datetime.utcnow() - created).days
            if days_old > 365:
                status = 1
                desc   = f"AMI is {days_old} days old"
            elif days_old > 800:
                status = 2
                desc   = f"AMI is {days_old} days old (unsupported)"
            else:
                status = 0
                desc   = "AMI under 1 year old"
        except Exception:
            status = 3
            desc   = "Unable to parse AMI creation date"
        self._add('outdated_ami', status, desc, iid)

        # SSM fleet
        managed = iid in ssm_managed
        self._add('ssm_managed', 0 if managed else 1,
                  "SSM managed" if managed else "Not registered in SSM", iid)

    def _check_keypairs(self, key_pairs):
        threshold = datetime.utcnow() - timedelta(days=180)
        for kp in key_pairs:
            name   = kp.get("KeyName")
            ctime  = kp.get("CreateTime")
            if not ctime:
                self._add('stale_keypair', 3, "CreateTime unavailable", name)
                continue
            age = (datetime.utcnow() - ctime.replace(tzinfo=None)).days
            if age > 365:
                self._add('stale_keypair', 2, f"Key age {age} days (≥1 year)", name)
            elif age > 180:
                self._add('stale_keypair', 1, f"Key age {age} days (>180)", name)
            else:
                self._add('stale_keypair', 0, f"Key age {age} days", name)

    def _check_lifecycle(self, inst, allowed_regions):
        iid = inst["InstanceId"]
        reg = inst.get("Region")
        stopped = inst.get("State") == "stopped"

        if stopped:
            self._add('unused_instance', 1, "Instance is stopped", iid)
        else:
            self._add('unused_instance', 0, "Instance running", iid)

        if reg not in allowed_regions:
            self._add('unused_instance', 2, f"Running in disallowed region {reg}", iid)

    # ------------------ orchestrator ------------------------------- #
    def run(self, cache, settings, callback):
        try:
            data   = cache.get('ec2', {})
            insts  = data.get("Instances", [])
            vols   = data.get("Volumes", {})
            amis   = data.get("AMIs", {})
            snaps  = data.get("Snapshots", [])
            flow   = data.get("FlowLogs", [])
            ssm_m  = data.get("SSMManaged", [])
            role_docs = data.get("RolePolicyDocs", {})
            key_pairs = data.get("KeyPairs", [])
            allowed_regions = settings.get("allowed_regions", [settings["region"]])

            # build helpers
            snap_by_vol = defaultdict(list)
            for s in snaps:
                if s.get("VolumeId"):
                    snap_by_vol[s["VolumeId"]].append(s)

            flow_map = {f.get("ResourceId"): True for f in flow}

            # CloudTrail global (fail/warn handled in collector-agnostic way)
            if data.get("Trails"):
                self._add('cloudtrail', 0, "CloudTrail trails found")
            else:
                self._add('cloudtrail', 2, "No CloudTrail trails found")

            unused_roles = set(data.get("AllRoles", []))

            for inst in insts:
                self._check_public_and_sg(inst)
                self._check_role(inst, role_docs, unused_roles)
                self._check_storage(inst, vols, amis, snap_by_vol)
                self._check_monitoring(inst, flow_map)
                self._check_patch(inst, amis, ssm_m)
                self._check_lifecycle(inst, allowed_regions)

            for rn in unused_roles:
                self._add('unused_role', 1, "Role not attached to any instance", rn)

            self._check_keypairs(key_pairs)

            callback(None, self.results, {})
        except Exception as e:
            callback(str(e), [], {})
