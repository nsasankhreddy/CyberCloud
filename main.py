# main.py
import os
from compliance_checks import run_compliance_checks
from misconfiguration_checks import check_aws_iam, check_aws_s3_buckets, check_aws_security_groups
from email_alert import send_email_alert
from utils.logger import get_logger
import boto3

logger = get_logger(__name__)

# Common AWS service clients
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

iam_client = boto3.client(
    'iam',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

ec2_client = boto3.client(
    'ec2',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

def generate_aws_security_report_and_send_alert():
    """Generate a report including compliance and misconfiguration checks with Remediation suggestions."""
    logger.info("Starting AWS security misconfiguration detection and compliance audit...\n")
    
    # Run misconfiguration checks
    iam_issues = check_aws_iam()
    s3_issues = check_aws_s3_buckets()
    sg_issues = check_aws_security_groups()
    
    # Run compliance checks
    compliance_issues = run_compliance_checks()
    
    # Combine all issues into a list of dictionaries
    all_issues = []
    for issue in iam_issues + s3_issues + sg_issues + compliance_issues:
        all_issues.append({
            "Type": issue[0],
            "Description": issue[1],
            "Remediation": issue[2] if len(issue) > 2 else "No Remediation provided"
        })

    # Prepare report for email
    report = "\n".join(f"{i['Type']}: {i['Description']}\nSuggested Remediation: {i['Remediation']}" for i in all_issues)
    logger.info(f"Misconfigurations and compliance issues found: \n{report}")
    
    # Send email if issues are found
    if all_issues:
        send_email_alert("AWS Security & Compliance Issues Detected", report, os.getenv('RECIPIENT_EMAIL'))
        logger.info("AWS security issues found and reported!")
    else:
        logger.info("No AWS misconfigurations or compliance issues detected.")
    
    return all_issues  # Return issues for database logging
