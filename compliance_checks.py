import boto3
from botocore.exceptions import ClientError

# Check if all IAM users have MFA enabled
def check_iam_mfa_compliance():
    print("Checking IAM users for MFA compliance...")
    iam_client = boto3.client('iam')
    users = iam_client.list_users()['Users']
    issues = []
    
    for user in users:
        mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            issues.append(f"IAM user {user['UserName']} does not have MFA enabled.")
            print(f"  -> Issue: IAM user {user['UserName']} lacks MFA.")
        else:
            print(f"  -> No issues: IAM user {user['UserName']} has MFA enabled.")
    
    return issues

# Check if any S3 buckets are public
def check_s3_compliance():
    print("Checking S3 buckets for public access compliance...")
    s3_client = boto3.client('s3')
    buckets = s3_client.list_buckets()['Buckets']
    issues = []
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name).get('PolicyStatus')
            if policy_status and policy_status.get('IsPublic'):
                issues.append(f"S3 bucket {bucket_name} is publicly accessible.")
                print(f"  -> Issue: S3 bucket {bucket_name} is public.")
            else:
                print(f"  -> No issues: S3 bucket {bucket_name} is private.")
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                print(f"  -> Could not retrieve bucket policy for {bucket_name}: {e}")
    
    return issues

# Check if CloudTrail logging is enabled
def check_cloudtrail_logging():
    print("Checking CloudTrail logging compliance...")
    cloudtrail_client = boto3.client('cloudtrail')
    trails = cloudtrail_client.describe_trails()['trailList']
    issues = []
    
    for trail in trails:
        status = cloudtrail_client.get_trail_status(Name=trail['Name'])
        if not status.get('IsLogging'):
            issues.append(f"CloudTrail {trail['Name']} is not logging.")
            print(f"  -> Issue: CloudTrail {trail['Name']} is not active.")
        else:
            print(f"  -> No issues: CloudTrail {trail['Name']} is logging.")
    
    return issues

# Function to run all compliance checks
def run_compliance_checks():
    print("Running compliance checks...")
    compliance_issues = []
    compliance_issues.extend(check_iam_mfa_compliance())
    compliance_issues.extend(check_s3_compliance())
    compliance_issues.extend(check_cloudtrail_logging())
    
    if compliance_issues:
        print("Compliance issues found:")
        for issue in compliance_issues:
            print(issue)
    else:
        print("All checks passed. AWS environment is compliant.")
    
    return compliance_issues
