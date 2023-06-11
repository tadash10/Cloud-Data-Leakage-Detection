# Cloud-Data-Leakage-Detection


This Python script scans cloud storage repositories, such as AWS S3 buckets or Azure Blob Storage, for sensitive data leaks. It utilizes pattern matching or machine learning techniques to identify personally identifiable information (PII), credit card numbers, or other confidential data. The script provides a summary of detected leaks and recommendations for remediation.

v3 update :version (v3.py) of the script that incorporates three of the requested improvements: error handling, logging, and enhanced data patterns. 
## ISO Standards Compliance

The Cloud Data Leakage Detection script aligns with the following ISO standards for cloud security:

- ISO/IEC 27001:2013 - Information security management systems - Requirements
- ISO/IEC 27017:2015 - Information technology - Security techniques - Code of practice for information security controls based on ISO/IEC 27002 for cloud services
- ISO/IEC 27018:2019 - Information technology - Security techniques - Code of practice for protection of personally identifiable information (PII) in public clouds acting as PII processors

The script adheres to ISO 27001 by implementing encryption at rest and in transit for cloud storage repositories. It also follows ISO 27017 and ISO 27018 by ensuring secure access controls and protecting personally identifiable information (PII).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/cloud-data-leakage-detection.git
Navigate to the project directory:
cd cloud-data-leakage-detection

Install the required Python packages:
pip install -r requirements.txt

Usage

To run the Cloud Data Leakage Detection script, execute the following command:
python cloud_data_leakage_detection.py
Certainly! Here's an example of a README file that includes ISO standards compliance information, installation instructions, and a guide on how to use the CLI:

rust

# Cloud Data Leakage Detection

This Python script scans cloud storage repositories, such as AWS S3 buckets or Azure Blob Storage, for sensitive data leaks. It utilizes pattern matching or machine learning techniques to identify personally identifiable information (PII), credit card numbers, or other confidential data. The script provides a summary of detected leaks and recommendations for remediation.

## ISO Standards Compliance

The Cloud Data Leakage Detection script aligns with the following ISO standards for cloud security:

- ISO/IEC 27001:2013 - Information security management systems - Requirements
- ISO/IEC 27017:2015 - Information technology - Security techniques - Code of practice for information security controls based on ISO/IEC 27002 for cloud services
- ISO/IEC 27018:2019 - Information technology - Security techniques - Code of practice for protection of personally identifiable information (PII) in public clouds acting as PII processors

The script adheres to ISO 27001 by implementing encryption at rest and in transit for cloud storage repositories. It also follows ISO 27017 and ISO 27018 by ensuring secure access controls and protecting personally identifiable information (PII).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/cloud-data-leakage-detection.git

    Navigate to the project directory:

    bash

cd cloud-data-leakage-detection

Install the required Python packages:

bash

    pip install -r requirements.txt

    Set up the necessary AWS credentials by configuring the AWS CLI or using environment variables. Refer to the AWS documentation for more information.

Usage

To run the Cloud Data Leakage Detection script, execute the following command:

bash

python cloud_data_leakage_detection.py

The script will present a menu with the following options:

    Scan S3 Buckets: Scans all S3 buckets for sensitive data leaks.
    Enable Encryption for a Bucket: Enables encryption for a specific S3 bucket.
    Disable Encryption for a Bucket: Disables encryption for a specific S3 bucket.
    Exit: Quits the script.

Choose the desired option by entering the corresponding number. Follow the prompts for enabling or disabling encryption and provide the necessary information when requested.

Please note that the script requires the appropriate AWS credentials with sufficient permissions to access and scan the S3 buckets.


The script has a total of 11 functions:

    get_s3_client(): Creates and returns an S3 client with the appropriate configuration.
    get_s3_buckets(): Retrieves a list of S3 buckets to scan.
    scan_s3_bucket(bucket_name): Scans an S3 bucket for sensitive data leaks.
    configure_iam_role(): Configures the IAM role for secure access controls.
    enable_bucket_encryption(bucket_name): Enables encryption for an S3 bucket.
    disable_bucket_encryption(bucket_name): Disables encryption for an S3 bucket.
    print_menu(): Prints the menu options.
    process_menu_choice(choice): Processes the user's menu choice.
    main(): The main function that orchestrates the execution of the script.
    print_disclaimer(): Prints the disclaimer message.
    exit_program(): Exits the program.
