# ec2_collector.py
#
# Gather EC2-related telemetry for CSPM:
#   • Instance inventory (public IPs, SG rules, EBS encryption, IAM role, AMI, etc.)
#   • VPC Flow-log status
#   • CloudTrail trails
#   • Key-pair metadata
#   • SSM-managed instance IDs
#   • Snapshots (encryption / public)
#   • IAM role policy docs for every instance-profile role
#
# Callback signature:  callback(err, data)

import time, json, boto3
from collections import defaultdict
from botocore.exceptions import ClientError

def get_ec2_config_details(aws_cfg: dict, callback):
    try:
        reg = aws_cfg.get("region")
        ec2   = boto3.client("ec2",
                aws_access_key_id=aws_cfg["access_key"],
                aws_secret_access_key=aws_cfg["secret_key"],
                aws_session_token=aws_cfg.get("session_token"),
                region_name=reg)

        iam   = boto3.client("iam",
                aws_access_key_id=aws_cfg["access_key"],
                aws_secret_access_key=aws_cfg["secret_key"],
                aws_session_token=aws_cfg.get("session_token"),
                region_name=reg)

        ct    = boto3.client("cloudtrail",
                aws_access_key_id=aws_cfg["access_key"],
                aws_secret_access_key=aws_cfg["secret_key"],
                aws_session_token=aws_cfg.get("session_token"),
                region_name=reg)

        ssm   = boto3.client("ssm",
                aws_access_key_id=aws_cfg["access_key"],
                aws_secret_access_key=aws_cfg["secret_key"],
                aws_session_token=aws_cfg.get("session_token"),
                region_name=reg)

        # ------------------------------------------------------------------ #
        # 1) CloudTrail & Flow-logs                                          #
        # ------------------------------------------------------------------ #
        try:
            trails = ct.describe_trails(includeShadowTrails=True)["trailList"]
        except ClientError:
            trails = []

        flow_logs = []
        try:
            flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        except ClientError:
            pass

        # ------------------------------------------------------------------ #
        # 2) SSM managed instances                                           #
        # ------------------------------------------------------------------ #
        ssm_managed = []
        try:
            paginator = ssm.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                ssm_managed.extend([i["InstanceId"] for i in page["InstanceInformationList"]])
        except ClientError:
            pass

        # ------------------------------------------------------------------ #
        # 3) Key pairs                                                       #
        # ------------------------------------------------------------------ #
        try:
            key_pairs = ec2.describe_key_pairs()["KeyPairs"]
        except ClientError:
            key_pairs = []

        # ------------------------------------------------------------------ #
        # 4) Instances (+ vols / SG / IAM role)                              #
        # ------------------------------------------------------------------ #
        instances     = []
        all_volume_ids = set()
        role_names     = set()
        ami_ids        = set()
        vpc_ids        = set()

        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for r in page["Reservations"]:
                for inst in r["Instances"]:
                    iid   = inst["InstanceId"]
                    vpc   = inst.get("VpcId")
                    vpc_ids.add(vpc)

                    # public exposure
                    pub_ip  = inst.get("PublicIpAddress")
                    eip_allocation = inst.get("NetworkInterfaces", [{}])[0].get("Association", {}).get("AllocationId")

                    # security groups + ingress rules snapshot
                    sg_info = []
                    for sg in inst.get("SecurityGroups", []):
                        try:
                            full = ec2.describe_security_groups(GroupIds=[sg["GroupId"]])["SecurityGroups"][0]
                            sg_info.append(full)
                        except ClientError:
                            sg_info.append({"GroupId": sg["GroupId"], "Error": "Could not retrieve"})

                    # instance-profile role(s)
                    roles = []
                    if "IamInstanceProfile" in inst:
                        ip_arn = inst["IamInstanceProfile"]["Arn"]
                        try:
                            ip = iam.get_instance_profile(InstanceProfileName=ip_arn.split("/")[-1])["InstanceProfile"]
                            roles = [r["RoleName"] for r in ip["Roles"]]
                            role_names.update(roles)
                        except ClientError:
                            pass

                    # block-devices → volumes
                    vols = [bdm["Ebs"]["VolumeId"] for bdm in inst.get("BlockDeviceMappings", []) if "Ebs" in bdm]
                    all_volume_ids.update(vols)

                    instances.append({
                        "InstanceId": iid,
                        "Region": reg,
                        "State": inst["State"]["Name"],
                        "LaunchTime": inst["LaunchTime"].isoformat(),
                        "InstanceType": inst["InstanceType"],
                        "PublicIp": pub_ip,
                        "ElasticIpAllocation": eip_allocation,
                        "SecurityGroups": sg_info,
                        "VpcId": vpc,
                        "SubnetId": inst.get("SubnetId"),
                        "IamRoles": roles,
                        "KeyName": inst.get("KeyName"),
                        "Monitoring": inst.get("Monitoring", {}).get("State"),
                        "ImageId": inst.get("ImageId"),
                        "Volumes": vols
                    })
                    if inst.get("ImageId"):
                        ami_ids.add(inst["ImageId"])

        # ------------------------------------------------------------------ #
        # 5) Volume encryption                                               #
        # ------------------------------------------------------------------ #
        volumes = {}
        if all_volume_ids:
            for i in range(0, len(all_volume_ids), 200):
                chunk = list(all_volume_ids)[i:i+200]
                try:
                    for v in ec2.describe_volumes(VolumeIds=chunk)["Volumes"]:
                        volumes[v["VolumeId"]] = {
                            "Encrypted": v["Encrypted"],
                            "SnapshotId": v["SnapshotId"] if "SnapshotId" in v else None
                        }
                except ClientError:
                    pass

        # ------------------------------------------------------------------ #
        # 6) Snapshot metadata (encryption/share)                            #
        # ------------------------------------------------------------------ #
        snapshots = []
        try:
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for s in page["Snapshots"]:
                    snapshots.append({
                        "SnapshotId": s["SnapshotId"],
                        "Encrypted": s["Encrypted"],
                        "VolumeId":  s.get("VolumeId"),
                        "Public":    len(s.get("CreateVolumePermissions", [])) > 0
                    })
        except ClientError:
            pass

        # ------------------------------------------------------------------ #
        # 7) AMI details                                                     #
        # ------------------------------------------------------------------ #
        amis = {}
        if ami_ids:
            try:
                for img in ec2.describe_images(ImageIds=list(ami_ids))["Images"]:
                    amis[img["ImageId"]] = {
                        "Public": img["Public"],
                        "CreationDate": img.get("CreationDate"),
                        "Name": img.get("Name", "")
                    }
            except ClientError:
                pass

        # ------------------------------------------------------------------ #
        # 8) IAM role policy documents (for least-privilege scan)           #
        # ------------------------------------------------------------------ #
        policy_cache = {}
        def get_managed_doc(arn):
            if arn in policy_cache:
                return policy_cache[arn]
            try:
                meta   = iam.get_policy(PolicyArn=arn)["Policy"]
                ver    = iam.get_policy_version(PolicyArn=arn,
                                                VersionId=meta["DefaultVersionId"])["PolicyVersion"]["Document"]
            except ClientError:
                ver = {}
            policy_cache[arn] = ver
            return ver

        role_policy_docs = {}
        for rn in role_names:
            try:
                role = iam.get_role(RoleName=rn)["Role"]
                inline = {}
                try:
                    names = iam.list_role_policies(RoleName=rn)["PolicyNames"]
                    inline = {n: iam.get_role_policy(RoleName=rn, PolicyName=n)["PolicyDocument"] for n in names}
                except ClientError:
                    pass
                attached_arns = []
                managed = {}
                try:
                    attached_arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=rn)["AttachedPolicies"]]
                    managed = {arn: get_managed_doc(arn) for arn in attached_arns}
                except ClientError:
                    pass
                role_policy_docs[rn] = {"Inline": inline, "Managed": managed}
            except ClientError:
                role_policy_docs[rn] = {}

        data = {
            "Instances": instances,
            "Volumes": volumes,
            "Snapshots": snapshots,
            "AMIs": amis,
            "Trails": trails,
            "FlowLogs": flow_logs,
            "SSMManaged": ssm_managed,
            "KeyPairs": key_pairs,
            "RolePolicyDocs": role_policy_docs,
            "AllRoles": list(role_names)
        }
        callback(None, data)

    except Exception as e:
        callback(str(e), {})
