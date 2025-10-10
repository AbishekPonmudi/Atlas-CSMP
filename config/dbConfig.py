import os
import boto3
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error


load_dotenv("dev.env")
status_info = None

def db_connection(Access_key, Secret_key, Region,status):
    connection = None
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',
            database=os.getenv("DATABASE"),
            user=os.getenv("USER"),
            password=os.getenv("PASSWORD"),
        )
        
        if connection.is_connected():
            
            db_info = connection.get_server_info()
            print(f"Connected to Mysql Server {db_info}")
            
            insert_query = """INSERT INTO client (access_key,secret_key,region,status) VALUES (%s,%s,%s,%s)"""
            record = (Access_key, Secret_key,Region, status)
            cursor = connection.cursor()
            cursor.execute(insert_query, record)
            connection.commit()
            print(f"Done sucessfully")
            cursor.close()
        
    except Error as e:
        print(f"Error while connecting to db 10: {e}")
    
    finally:
        if connection.is_connected():
            connection.close()
            print("Connection closed...")   
            
def get_config_status():
    try:      
        connection = mysql.connector.connect(
            host='127.0.0.1',
            database=os.getenv("DATABASE"),
            user=os.getenv("USER"),
            password=os.getenv("PASSWORD"),
        )  
        
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute("SELECT status FROM client ORDER BY id DESC LIMIT 1")
            result = cursor.fetchone()
            if result:
                global status_info
                status_info = 'ok'
                return result[0]
            
            else:
                return False   
    except Error as e:
        print(f"Error while connecting to db 11: {e}")
        return None
    
    finally:
        if connection.is_connected():
            connection.close()
            print("Activation connection successed...")
            print("Please wait, this may take a while...")

# db_connection("test-access-key","test-access-key","test-region")  # for testing purposes

def get_config():
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',
            database=os.getenv("DATABASE"),
            user=os.getenv("USER"),
            password=os.getenv("PASSWORD"),
        )
        if connection.is_connected():
            cursor  = connection.cursor(dictionary=True)
            cursor.execute("SELECT access_key, secret_key, region FROM client ORDER BY id DESC LIMIT 1")
            result = cursor.fetchone()
            if result:
                return {
                    'access_key': result["access_key"],
                    'secret_key': result["secret_key"],
                    'region': result["region"]
                }
            else:
                print("Having issue with fetching configuration")
                return None
    except Error as e:
        print(f"Error while connecting to db 12: {e}")
        return None

    finally:
        if connection.is_connected():
            connection.close()
            
def status_verify():
    global status_info
    if status_info is None:
        status_info = get_config_status()
    if status_info:
        print("[+] CSPM is active and running")
    else:
        print("[-] CSPM is not active, please run 'aws config' to configure your AWS credentials.")
        return False
    return True

def get_account_name(): 
    try:
        AWSconfig = get_config()
        # required_keys = ['access_key', 'secret_key', 'region']
        # if not all(key in AWSconfig for key in required_keys):
        #     print(f"Error: Missing required config keys. Found: {list(AWSconfig.keys())}")
        #     return None

        session = boto3.Session(
            aws_access_key_id=AWSconfig['access_key'],
            aws_secret_access_key=AWSconfig['secret_key'],
            region_name=AWSconfig['region']
        )
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']

        return account_id
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return None