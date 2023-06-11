import re
import boto3
from botocore.exceptions import ClientError

# Define the sensitive data patterns to match against
patterns = {
    'PII': r'\b\d{3}-?\d{2}-?\d{4}\b',  # Social Security Numbers (SSN) pattern
    'Credit Card': r'\b(?:\d{4}-?){3}(?:\d{4})\b',  # Credit card numbers pattern
    # Add more patterns as needed for other sensitive data types
}

def scan_s3_bucket(bucket_name):
    s3 = boto3.client('s3')

    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            print(f"No objects found in bucket: {bucket_name}")
            return
        
        for obj in response['Contents']:
            object_key = obj['Key']
            try:
                response = s3.get_object(Bucket=bucket_name, Key=object_key)
                content = response['Body'].read().decode('utf-8')

                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        print(f"Sensitive data leak detected in {bucket_name}/{object_key}:")
                        print(f"- Pattern: {pattern_name}")
                        print(f"- Matches: {matches}")
                        print()
                
            except ClientError as e:
                print(f"Error accessing object {bucket_name}/{object_key}: {e}")
    
    except ClientError as e:
        print(f"Error listing objects in bucket {bucket_name}: {e}")

def main():
    # List of S3 buckets to scan
    buckets = ['bucket1', 'bucket2', 'bucket3']

    for bucket_name in buckets:
        print(f"Scanning S3 bucket: {bucket_name}")
        scan_s3_bucket(bucket_name)
        print()

if __name__ == "__main__":
    main()
