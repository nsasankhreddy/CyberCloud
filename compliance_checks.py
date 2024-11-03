import boto3
from botocore.exceptions import ClientError
from utils.logger import get_logger
from database_helpers import save_issue  # Import save_issue function to store issues in the database

logger = get_logger(__name__)

def check_iam_mfa_compliance():
    """Ensure all IAM users have MFA enabled."""
    logger.info("Checking IAM users for MFA compliance...")
    iam_client = boto3.client('iam')
    users = iam_client.list_users()['Users']
    issues = []
    
    for user in users:
        mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            issue = f"IAM user {user['UserName']} does not have MFA enabled."
            remediation = "Enable MFA for this IAM user in the IAM console."
            issues.append((issue, remediation))
            save_issue("IAM Policy", issue, remediation)  # Save the issue to the database
            logger.warning(issue)
        else:
            logger.info(f"IAM user {user['UserName']} has MFA enabled.")
    
    return issues

def check_s3_compliance():
    """Ensure no public S3 buckets are accessible."""
    logger.info("Checking S3 buckets for public access compliance...")
    s3_client = boto3.client('s3')
    buckets = s3_client.list_buckets()['Buckets']
    issues = []
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name).get('PolicyStatus')
            if policy_status and policy_status.get('IsPublic'):
                issue = f"S3 bucket {bucket_name} is publicly accessible."
                remediation = "Make the S3 bucket private using S3 bucket policies or ACL."
                issues.append((issue, remediation))
                save_issue("S3 Bucket", issue, remediation)  # Save the issue to the database
                logger.warning(issue)
            else:
                logger.info(f"S3 bucket {bucket_name} is private.")
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                logger.error(f"Could not retrieve bucket policy for {bucket_name}: {e}")
    
    return issues

def check_cloudtrail_logging():
    """Ensure CloudTrail is enabled and logging."""
    logger.info("Checking CloudTrail logging compliance...")
    cloudtrail_client = boto3.client('cloudtrail')
    trails = cloudtrail_client.describe_trails()['trailList']
    issues = []
    
    for trail in trails:
        status = cloudtrail_client.get_trail_status(Name=trail['Name'])
        if not status.get('IsLogging'):
            issue = f"CloudTrail {trail['Name']} is not logging."
            remediation = "Enable logging for CloudTrail in the CloudTrail console."
            issues.append((issue, remediation))
            save_issue("CloudTrail", issue, remediation)  # Save the issue to the database
            logger.warning(issue)
        else:
            logger.info(f"CloudTrail {trail['Name']} is logging.")
    
    return issues

def run_compliance_checks():
    """Run all compliance checks and return issues with remediation suggestions."""
    logger.info("Running compliance checks...")
    compliance_issues = []
    compliance_issues.extend(check_iam_mfa_compliance())
    compliance_issues.extend(check_s3_compliance())
    compliance_issues.extend(check_cloudtrail_logging())
    
    if compliance_issues:
        logger.warning("Compliance issues found.")
    else:
        logger.info("All checks passed. AWS environment is compliant.")
    
    return compliance_issues
