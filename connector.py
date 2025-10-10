#This is the connector module for AWS configuration and database connection management.
# This module handles the configuration of AWS credentials and manages the connection to a database for storing these credentials.

import getpass
import config.dbConfig as dbConfig
import main


def aws_config_creds():
    
    access_key = input("Enter your AWS Access Key: ").strip()
    
    while not access_key:
        print("Access Key cannot be empty.")
        access_key = input("Enter your AWS Access Key: ")
    while len(access_key) < 16:
        print("Access Key must be at least 16 characters long.")
        access_key = input("Enter your AWS Access Key: ")
    while len(access_key) > 128:
        print("Access Key must be no more than 128 characters long.")
        access_key = input("Enter your AWS Access Key: ")
    while not access_key.isalnum():
        print("Access Key must be alphanumeric.")
        access_key = input("Enter your AWS Access Key: ")
        
        
    secret_key = input("Enter your AWS Secret Key: ").strip()
    
    while not secret_key:
        print("Secret Key cannot be empty.")
        secret_key = input("Enter your AWS Secret Key: ")
    while len(secret_key) < 16:
        print("Secret Key must be at least 16 characters long.")
        secret_key = input("Enter your AWS Secret Key: ")
    while len(secret_key) > 128:
        print("Secret Key must be no more than 128 characters long.")
        secret_key = input("Enter your AWS Secret Key: ")
    
    print(f"{main.BLUE}Mention specific or All region{main.RESET}")
    region = input("Enter your AWS Region: ")
    
    while not region:
        print("Region cannot be empty.")
        region = input("Enter your AWS Region: ")
    
    credintials = {
        "access_key": access_key,
        "secret_key": secret_key,
        "region": region
    }
    
    try:
        dbConfig.db_connection(access_key, secret_key, region,True)
    except Exception as e:  
        print(f"Error while connecting to the database: {e}")
        return None
    
    print("Credentials have been successfully configured.")
    return credintials

def db_status_set(state):
    status = state
    
def db_status():
    return dbConfig.get_config_status()

# def get_config():
#     db_config = dbConfig.get_config()
#     if db_config:
#         return {
#             'access_key': db_config['access_key'],
#             'secret_key': db_config['secret_key'],
#             'region': db_config['region']
#         }
#     else:
#         print("No configuration found in the database.")
#         return None
    
    