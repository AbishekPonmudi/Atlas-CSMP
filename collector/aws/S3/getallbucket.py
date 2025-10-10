# This code is part of a collector module that retrieves bucket policies from AWS S3.
# It uses the boto3 library to interact with AWS services and handles exceptions for missing policies.
# collector/getallbucket.py

 #Get all bucket policies from AWS S3

import json
import boto3
from botocore.exceptions import ClientError

def get_bucket_policy(AWSconfig, callback):
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=AWSconfig['access_key'],
            aws_secret_access_key=AWSconfig['secret_key'],
            region_name=AWSconfig['region']
        )

        buckets = s3.list_buckets().get('Buckets',[])
        if not buckets:
            callback(None,[])
            return
        
        bucket_data_list = []
        for bucket in buckets:
            name = bucket['Name']
            
            # to get the bucket region if not use the default configuration data
            try:
                location = s3.get_bucket_location(Bucket=name).get('LocationConstraint',AWSconfig['region'])
                location = location or AWSconfig['region']
            except ClientError:
                location = AWSconfig['region']
            
            bucket_data = {
                "Name": name,
                "Region": location,
                "Encryption" : None,
                "MFADelete" : None,
                "AccessLogging": None,
                "BlockPublicAccess": None,
                "Policy": None,
                "ACL": None
            }
            
            #get bucket policy data
            
            try:
                policy_response = s3.get_bucket_policy(Bucket=name)
                bucket_data['Policy'] = json.loads(policy_response['Policy'])
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    bucket_data["Policy"] = None
                else:
                    bucket_data["Policy"] = f"error : {e.response['Error']['Message']}"
                    
            # Get ACL
            try:
                bucket_data["ACL"] = s3.get_bucket_acl(Bucket=name)
            except ClientError as e:
                bucket_data["ACL"] = f"Error: {e.response['Error']['Message']}"

            # Get encryption
            try:
                encryption = s3.get_bucket_encryption(Bucket=name)
                bucket_data["Encryption"] = encryption.get("ServerSideEncryptionConfiguration", {})
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    bucket_data["Encryption"] = None
                else:
                    bucket_data["Encryption"] = f"Error: {e.response['Error']['Message']}"

            # Get MFA Delete
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                bucket_data["MFADelete"] = versioning.get("MFADelete", "Disabled")
            except ClientError as e:
                bucket_data["MFADelete"] = f"Error: {e.response['Error']['Message']}"

            # Get access logging
            try:
                logging = s3.get_bucket_logging(Bucket=name)
                bucket_data["AccessLogging"] = bool(logging.get("LoggingEnabled"))
            except ClientError as e:
                bucket_data["AccessLogging"] = f"Error: {e.response['Error']['Message']}"

            # Get public access block
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
    
    # this is for testing purpose
    
    def print_results(err, buckets):
        if err:
            print(f"[ERROR] {err}")
            return
        
    from config.dbConfig import get_config
    aws_config = get_config()
    get_bucket_policy(aws_config, print_results)