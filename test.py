import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import json
from collections import defaultdict
import concurrent.futures
import threading
from config.dbConfig import get_config

class AWSResourceCounter:
    @staticmethod
    def create_session():
        AWSConfig = get_config()
        return boto3.Session(
            aws_access_key_id=AWSConfig['access_key'],
            aws_secret_access_key=AWSConfig['secret_key'],
            region_name=AWSConfig['region']
        )

    @staticmethod
    def get_all_regions(session):
        try:
            ec2 = session.client('ec2', region_name='us-east-1')
            regions = ec2.describe_regions()
            return [region['RegionName'] for region in regions['Regions']]
        except Exception:
            return ['us-east-1', 'ap-south-1', 'eu-west-1']

    @staticmethod
    def count_regional_resources(region, session, total_counts, lock):
        regional_counts = {}
        try:
            ec2 = session.client('ec2', region_name=region)
            instances = ec2.describe_instances()
            instance_count = sum(len(reservation['Instances']) for reservation in instances['Reservations'])
            regional_counts['EC2 Instances'] = instance_count

            volumes = ec2.describe_volumes()
            regional_counts['EBS Volumes'] = len(volumes['Volumes'])

            sgs = ec2.describe_security_groups()
            regional_counts['Security Groups'] = len(sgs['SecurityGroups'])

            keys = ec2.describe_key_pairs()
            regional_counts['Key Pairs'] = len(keys['KeyPairs'])

            vpcs = ec2.describe_vpcs()
            regional_counts['VPCs'] = len(vpcs['Vpcs'])

            subnets = ec2.describe_subnets()
            vpc_ids_with_subnets = {s['VpcId'] for s in subnets['Subnets']}
            regional_counts['Subnets'] = len(vpc_ids_with_subnets)

            igws = ec2.describe_internet_gateways()
            regional_counts['Internet Gateways'] = len(igws['InternetGateways'])

            route_tables = ec2.describe_route_tables()
            regional_counts['Route Tables'] = len(route_tables['RouteTables'])

            eips = ec2.describe_addresses()
            regional_counts['Elastic IPs'] = len(eips['Addresses'])

            amis = ec2.describe_images(Owners=['self'])
            regional_counts['AMIs'] = len(amis['Images'])
        except Exception as e:
            print(f"Error in region {region}: {e}")

        try:
            lambda_client = session.client('lambda', region_name=region)
            functions = lambda_client.list_functions()
            regional_counts['Lambda Functions'] = len(functions['Functions'])
        except Exception:
            pass

        try:
            rds = session.client('rds', region_name=region)
            instances = rds.describe_db_instances()
            regional_counts['RDS Instances'] = len(instances['DBInstances'])

            clusters = rds.describe_db_clusters()
            regional_counts['RDS Clusters'] = len(clusters['DBClusters'])

            snapshots = rds.describe_db_snapshots()
            regional_counts['RDS Snapshots'] = len(snapshots['DBSnapshots'])
        except Exception:
            pass

        try:
            cf = session.client('cloudformation', region_name=region)
            stacks = cf.list_stacks(StackStatusFilter=[
                'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'CREATE_IN_PROGRESS',
                'UPDATE_IN_PROGRESS', 'ROLLBACK_COMPLETE'
            ])
            regional_counts['CloudFormation Stacks'] = len(stacks['StackSummaries'])
        except Exception:
            pass

        try:
            cw = session.client('cloudwatch', region_name=region)
            alarms = cw.describe_alarms()
            regional_counts['CloudWatch Alarms'] = len(alarms['MetricAlarms'])
        except Exception:
            pass

        with lock:
            for resource_type, count in regional_counts.items():
                total_counts[resource_type] += count

    @staticmethod
    def count_global_resources(session, total_counts, lock):
        global_counts = {}
        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets()
            global_counts['S3 Buckets'] = len(buckets['Buckets'])
        except Exception:
            pass

        try:
            iam = session.client('iam')
            global_counts['IAM Users'] = len(iam.list_users()['Users'])
            global_counts['IAM Groups'] = len(iam.list_groups()['Groups'])
            global_counts['IAM Roles'] = len(iam.list_roles()['Roles'])
            global_counts['IAM Policies'] = len(iam.list_policies(Scope='Local')['Policies'])
        except Exception:
            pass

        with lock:
            for resource_type, count in global_counts.items():
                total_counts[resource_type] = count

    @staticmethod
    def run_count(max_workers=10):
        session = AWSResourceCounter.create_session()
        total_counts = defaultdict(int)
        lock = threading.Lock()

        regions = AWSResourceCounter.get_all_regions(session)
        AWSResourceCounter.count_global_resources(session, total_counts, lock)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(AWSResourceCounter.count_regional_resources, region, session, total_counts, lock)
                for region in regions
            ]
            concurrent.futures.wait(futures)

        return total_counts

    @staticmethod
    def print_totals(total_counts):
        sorted_resources = sorted(total_counts.items(), key=lambda x: x[1], reverse=True)

        for resource_type, count in sorted_resources:
            if count > 0:
                print(f"{resource_type:<30}: {count:>6}")

        grand_total = sum(total_counts.values())
        # print(f"{'TOTAL RESOURCES':<30}: {grand_total:>6}")
        return grand_total
