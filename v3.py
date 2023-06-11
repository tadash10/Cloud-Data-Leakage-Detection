import re
import boto3
import logging
from botocore.exceptions import ClientError

# ISO 27001 standard requires encryption at rest and transit
ENCRYPTION_REQUIRED = True

# ISO 27001 standard requires secure access controls
IAM_ROLE_ARN = 'arn:aws:iam::123456789012:role/CloudDataLeakageDetectionRole'

# Define the sensitive data patterns to match against
patterns = {
    'PII': r'\b\d{3}-?\d{2}-?\d{4}\b',  # Social Security Numbers (SSN) pattern
    'Credit Card': r'\b(?:\d{4}-?){3}(?:\d{4})\b',  # Credit card numbers pattern
    'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email pattern
    # Add more patterns as needed for other sensitive data types
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_s3_client():
    """
    Creates and returns an S3 client with the appropriate configuration.
    """
    session = boto3.Session()
    if ENCRYPTION_REQUIRED:
        s3 = session.client('s3', config=boto3.session.Config(s3={'use_accelerate_endpoint': True}))
    else:
        s3 = session.client('s3')
    return s3

def get_s3_buckets():
    """
    Retrieves a list of S3 buckets to scan.
    """
    s3 = get_s3_client()

    try:
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        return buckets
    
    except ClientError as e:
        logging.error(f"Error listing S3 buckets: {e}")
        return []

def scan_s3_bucket(bucket_name):
    """
    Scans an S3 bucket for sensitive data leaks.
    """
    s3 = get_s3_client()

    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            logging.info(f"No objects found in bucket: {bucket_name}")
            return
        
        for obj in response['Contents']:
            object_key = obj['Key']
            try:
                response = s3.get_object(Bucket=bucket_name, Key=object_key)
                content = response['Body'].read().decode('utf-8')

                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        logging.warning(f"Sensitive data leak detected in {bucket_name}/{object_key}:")
                        logging.warning(f"- Pattern: {pattern_name}")
                        logging.warning(f"- Matches: {matches}")
                        logging.warning('')
                
            except ClientError as e:
                logging.error(f"Error accessing object {bucket_name}/{object_key}: {e}")
    
    except ClientError as e:
        logging.error(f"Error listing objects in bucket {bucket_name}: {e}")

def configure_iam_role():
    """
    Configures the IAM role for secure access controls.
    """
    iam = boto3.client('iam')

    try:
        iam.update_assume_role_policy(
            RoleName='CloudDataLeakageDetectionRole',
            PolicyDocument='''{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "s3.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }'''
        )
        logging.info("IAM role configuration updated.")
    
    except ClientError as e:
        logging.error(f"Error configuring IAM role: {e}")

def enable_bucket_encryption(bucket_name):
    """
    Enables encryption for an S3 bucket.
    """
    s3 = get_s3_client()

    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        logging.info(f"Encryption enabled for bucket: {bucket_name}")
    
    except ClientError as e:
        logging.error(f"Error enabling encryption for bucket {bucket_name}: {e}")

def disable_bucket_encryption(bucket_name):
    """
    Disables encryption for an S3 bucket.
    """
    s3 = get_s3_client()

    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={}
        )
        logging.info(f"Encryption disabled for bucket: {bucket_name}")
    
    except ClientError as e:
        logging.error(f"Error disabling encryption for bucket {bucket_name}: {e}")

def print_menu():
    """
    Prints the menu options.
    """
    print("Cloud Data Leakage Detection Menu:")
    print("1. Scan S3 Buckets")
    print("2. Enable Encryption for a Bucket")
    print("3. Disable Encryption for a Bucket")
    print("4. Exit")

def process_menu_choice(choice):
    """
    Processes the user's menu choice.
    """
    if choice == '1':
        buckets = get_s3_buckets()
        for bucket in buckets:
            print(f"Scanning S3 bucket: {bucket}")
            scan_s3_bucket(bucket)
            print()
    elif choice == '2':
        bucket_name = input("Enter the name of the bucket to enable encryption for: ")
        enable_bucket_encryption(bucket_name)
    elif choice == '3':
        bucket_name = input("Enter the name of the bucket to disable encryption for: ")
        disable_bucket_encryption(bucket_name)
    elif choice == '4':
        print("Exiting...")
        exit()
    else:
        print("Invalid choice. Please try again.")

def main():
    disclaimer = """
    DISCLAIMER: This script is provided for educational purposes only. Use at your own risk.
    The author is not responsible for any unauthorized use or consequences of using this script.
    """

    print(disclaimer)

    while True:
        print_menu()
        choice = input("Enter your choice (1-4): ")
        process_menu_choice(choice)

if __name__ == "__main__":
    main()
    
    
    #Here's an updated version of the script that incorporates three of the requested improvements: error handling, logging, and enhanced data patterns.
    
