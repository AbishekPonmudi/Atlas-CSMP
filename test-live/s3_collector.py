import json
import boto3
from botocore.exceptions import ClientError
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from config.dbConfig import get_config

def get_s3_config_details(aws_config, callback):
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_config['access_key'],
            aws_secret_access_key=aws_config['secret_key'],
            region_name=aws_config['region']
        )

        buckets = s3.list_buckets().get('Buckets', [])
        if not buckets:
            callback(None, [])
            return

        bucket_data_list = []
        for bucket in buckets:
            name = bucket['Name']
            try:
                location = s3.get_bucket_location(Bucket=name).get('LocationConstraint', aws_config['region'])
                location = location or aws_config['region']
            except ClientError:
                location = aws_config['region']

            bucket_data = {
                "Name": name,
                "Region": location,
                "Encryption": None,
                "MFADelete": None,
                "AccessLogging": None,
                "BlockPublicAccess": None,
                "Policy": None,
                "ACL": None
            }

            try:
                policy_response = s3.get_bucket_policy(Bucket=name)
                bucket_data["Policy"] = json.loads(policy_response['Policy'])
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    bucket_data["Policy"] = None
                else:
                    bucket_data["Policy"] = f"Error: {e.response['Error']['Message']}"

            try:
                bucket_data["ACL"] = s3.get_bucket_acl(Bucket=name)
            except ClientError as e:
                bucket_data["ACL"] = f"Error: {e.response['Error']['Message']}"

            try:
                encryption = s3.get_bucket_encryption(Bucket=name)
                bucket_data["Encryption"] = encryption.get("ServerSideEncryptionConfiguration", {})
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    bucket_data["Encryption"] = None
                else:
                    bucket_data["Encryption"] = f"Error: {e.response['Error']['Message']}"
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                bucket_data["MFADelete"] = versioning.get("MFADelete", "Disabled")
            except ClientError as e:
                bucket_data["MFADelete"] = f"Error: {e.response['Error']['Message']}"

            try:
                logging = s3.get_bucket_logging(Bucket=name)
                bucket_data["AccessLogging"] = bool(logging.get("LoggingEnabled"))
            except ClientError as e:
                bucket_data["AccessLogging"] = f"Error: {e.response['Error']['Message']}"

            try:
                block_config = s3.get_public_access_block(Bucket=name)
                bucket_data["BlockPublicAccess"] = block_config.get("PublicAccessBlockConfiguration", {})
            except ClientError as e:
                if e.response['Error']['Code'] in ['NoSuchPublicAccessBlockConfiguration', 'AccessDenied', 'NoSuchBucket']:
                    bucket_data["BlockPublicAccess"] = None
                else:
                    bucket_data["BlockPublicAccess"] = f"Error: {e.response['Error']['Message']}"

            bucket_data_list.append(bucket_data)

        callback(None, bucket_data_list)

    except Exception as e:
        callback(str(e), [])

if __name__ == "__main__":
    
    
    def print_results(err, buckets):
        if err:
            print(f"[ERROR] {err}")
            return
        # for bucket in buckets:
    
            # print(f"Bucket Name       : {bucket['Name']}")
            # print(f"Region            : {bucket['Region']}")
            # print(f"Encryption Enabled: {'True' if bucket['Encryption'] else 'False'}")
            # print(f"MFA Delete        : {bucket['MFADelete']}")
            # print(f"Access Logging    : {bucket['AccessLogging']}")
            # print(f"Public Access     : {json.dumps(bucket['BlockPublicAccess'], indent=2)}")
            # print(f"Bucket Policy     : {json.dumps(bucket['Policy'], indent=2)}")
            # print(f"ACL               : {json.dumps(bucket['ACL'], indent=2)}")
            
    from config.dbConfig import get_config
    aws_config = get_config()
    get_s3_config_details(aws_config, print_results)