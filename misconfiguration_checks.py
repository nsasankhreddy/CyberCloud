import boto3
import os
import datetime
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AWS Misconfiguration Detection")

# Environment Configuration (Replace with actual environment variables or .env handling if required)
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "nsasankhreddy@gmail.com")
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL", "nandipatisasankhreddy@gmail.com")

# Function to detect overly permissive IAM policies
def check_aws_iam():
    """Detect overly permissive IAM policies with refined checks."""
    logger.info("Checking for overly permissive IAM policies...")

    iam_client = boto3.client('iam')
    policies = iam_client.list_policies(Scope='Local')['Policies']
    
    logger.info(f"Found {len(policies)} IAM policies.")
    
    issues = []
    sensitive_actions = ["s3:*", "ec2:*", "iam:*"]
    
    for policy in policies:
        logger.info(f"Checking policy: {policy['PolicyName']} ({policy['Arn']})")
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )
        document = policy_version['PolicyVersion']['Document']
        statements = document.get('Statement', [])
        statements = [statements] if not isinstance(statements, list) else statements

        for statement in statements:
            effect = statement.get('Effect')
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])
            actions = [actions] if not isinstance(actions, list) else actions
            resources = [resources] if not isinstance(resources, list) else resources

            if effect == 'Allow' and ('*' in actions or any(action in actions for action in sensitive_actions)) and '*' in resources:
                issue = f"Overly permissive IAM policy detected: {policy['PolicyName']}"
                issues.append(issue)
                logger.warning(issue)
            else:
                logger.info(f"No critical issues found in policy: {policy['PolicyName']}")

    logger.info(f"IAM check completed with {len(issues)} issues found.\n")
    return issues

# Function to detect publicly accessible S3 buckets
def check_aws_s3_buckets():
    """Detect publicly accessible S3 buckets."""
    logger.info("Checking for publicly accessible S3 buckets...")
    s3_client = boto3.client('s3')
    buckets = s3_client.list_buckets()['Buckets']
    
    logger.info(f"Found {len(buckets)} buckets.")
    
    issues = []
    for bucket in buckets:
        bucket_name = bucket['Name']
        logger.info(f"Checking bucket: {bucket_name}")

        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' and grant['Permission'] in ['READ', 'WRITE', 'FULL_CONTROL']:
                    issue = f"Public S3 bucket detected via ACL: {bucket_name}"
                    issues.append(issue)
                    logger.warning(issue)
                    break
            else:
                logger.info(f"No public ACL detected for {bucket_name}")
        except ClientError as e:
            logger.error(f"Could not retrieve ACL for {bucket_name}: {e}")

        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']
            if policy_status.get('IsPublic'):
                issue = f"Public bucket policy detected on bucket: {bucket_name}"
                issues.append(issue)
                logger.warning(issue)
            else:
                logger.info(f"Bucket policy is not public for {bucket_name}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucketPolicy':
                logger.info(f"No bucket policy for {bucket_name}.")
            else:
                logger.error(f"Could not retrieve bucket policy status for {bucket_name}: {str(e)}")
    
    logger.info(f"S3 bucket check completed with {len(issues)} issues found.\n")
    return issues

# Function to detect open security groups
def check_aws_security_groups():
    """Detect open security groups, focusing on high-risk ports."""
    logger.info("Checking for open security groups...")
    ec2_client = boto3.client('ec2')
    security_groups = ec2_client.describe_security_groups()['SecurityGroups']
    
    logger.info(f"Found {len(security_groups)} security groups.")
    
    issues = []
    high_risk_ports = [22, 80, 3389]
    
    for sg in security_groups:
        sg_name = sg.get('GroupName', 'Unnamed')
        sg_id = sg.get('GroupId')
        logger.info(f"Checking security group: {sg_name} ({sg_id})")

        for permission in sg['IpPermissions']:
            from_port = permission.get('FromPort')
            ip_ranges = permission.get('IpRanges', [])
            if from_port in high_risk_ports:
                for ip_range in ip_ranges:
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        issue = f"Insecure Security Group detected: {sg_name} ({sg_id}) allows port {from_port} from everywhere."
                        issues.append(issue)
                        logger.warning(issue)
                        break
                else:
                    logger.info(f"No public access detected for {sg_name} on high-risk ports.")
    logger.info(f"Security group check completed with {len(issues)} issues found.\n")
    return issues

# Function to send email alerts using SendGrid
def send_email_alert(subject, body):
    """Send detailed real-time email alerts using SendGrid"""
    logger.info("Preparing to send email alert...")

    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=RECIPIENT_EMAIL,
        subject=subject,
        plain_text_content=f"{body}\n\nDate/Time of detection: {datetime.datetime.now()}"
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        logger.info(f"Alert sent! Status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")

# Function to generate a report of AWS misconfigurations and send alerts
def generate_aws_security_report_and_send_alert():
    """Generate a report and send alerts if misconfigurations are detected"""
    logger.info("Starting AWS security misconfiguration detection...\n")

    # Run each check function
    iam_issues = check_aws_iam()
    s3_issues = check_aws_s3_buckets()
    sg_issues = check_aws_security_groups()

    # Combine all issues
    all_issues = iam_issues + s3_issues + sg_issues

    if all_issues:
        report = "\n".join(all_issues)
        logger.info(f"Misconfigurations found: \n{report}")
        send_email_alert("AWS Misconfiguration Detected", report)
        logger.info("AWS security issues found and reported!")
    else:
        logger.info("No AWS misconfigurations detected.")

if __name__ == "__main__":
    generate_aws_security_report_and_send_alert()
