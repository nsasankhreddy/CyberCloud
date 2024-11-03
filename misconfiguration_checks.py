import boto3
from botocore.exceptions import ClientError
from utils.logger import get_logger
from database_helpers import save_issue

logger = get_logger(__name__)

def check_aws_iam():
    """Detect overly permissive IAM policies with suggestions for remediation."""
    logger.info("Checking for overly permissive IAM policies...")
    iam_client = boto3.client('iam')
    policies = iam_client.list_policies(Scope='Local')['Policies']
    issues = []
    
    for policy in policies:
        try:
            policy_version = iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
            document = policy_version['PolicyVersion']['Document']
            for statement in document.get('Statement', []):
                effect = statement.get('Effect')
                actions = statement.get('Action')
                resources = statement.get('Resource')
                if effect == 'Allow' and ('*' in actions or '*' in resources):
                    issue = f"Overly permissive IAM policy detected: {policy['PolicyName']}"
                    remediation = "Restrict permissions in the IAM policy. Avoid using '*' for actions or resources."
                    issues.append((issue, remediation))
                    save_issue("IAM Policy", issue, remediation)  # Save to database
                    logger.warning(issue)
        except ClientError as e:
            logger.error(f"Could not retrieve policy version for {policy['PolicyName']}: {e}")
    
    logger.info(f"IAM check completed with {len(issues)} issues found.")
    return issues

def check_aws_s3_buckets():
    """Detect publicly accessible S3 buckets and provide remediation suggestions."""
    logger.info("Checking for publicly accessible S3 buckets...")
    s3_client = boto3.client('s3')
    buckets = s3_client.list_buckets()['Buckets']
    issues = []
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    issue = f"Public S3 bucket detected via ACL: {bucket_name}"
                    remediation = "Make this bucket private by modifying the ACL settings."
                    issues.append((issue, remediation))
                    save_issue("S3 Bucket", issue, remediation)  # Save to database
                    logger.warning(issue)
                    break
        except ClientError as e:
            logger.error(f"Could not retrieve ACL for {bucket_name}: {e}")
    
    logger.info(f"S3 bucket check completed with {len(issues)} issues found.")
    return issues

def check_aws_security_groups():
    """Detect open security groups with remediation suggestions."""
    logger.info("Checking for open security groups...")
    ec2_client = boto3.client('ec2')
    security_groups = ec2_client.describe_security_groups()['SecurityGroups']
    issues = []
    
    for sg in security_groups:
        for permission in sg['IpPermissions']:
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    issue = f"Insecure Security Group detected: {sg['GroupName']} allows access from everywhere."
                    remediation = "Restrict access to specific IP ranges. Avoid using 0.0.0.0/0."
                    issues.append((issue, remediation))
                    save_issue("Security Group", issue, remediation)  # Save to database
                    logger.warning(issue)
    
    logger.info(f"Security group check completed with {len(issues)} issues found.")
    return issues
