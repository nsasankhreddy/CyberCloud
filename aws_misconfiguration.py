import boto3
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from botocore.exceptions import ClientError

# Function to detect overly permissive IAM policies
def check_aws_iam():
    """Detect overly permissive IAM policies"""
    print("Checking for overly permissive IAM policies...")

    iam_client = boto3.client('iam')
    policies = iam_client.list_policies(Scope='Local')['Policies']
    
    print(f"Found {len(policies)} IAM policies.")
    
    issues = []
    for policy in policies:
        print(f"Checking policy: {policy['PolicyName']} ({policy['Arn']})")
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )
        document = policy_version['PolicyVersion']['Document']
        for statement in document.get('Statement', []):
            effect = statement.get('Effect')
            actions = statement.get('Action')
            resources = statement.get('Resource')
            # Detect overly permissive policy (e.g., actions or resources that allow "*")
            if effect == 'Allow' and ('*' in actions or '*' in resources):
                issues.append(f"Overly permissive IAM policy detected: {policy['PolicyName']}")
                print(f"  -> Issue found: {policy['PolicyName']} allows '*'.")
            else:
                print(f"  -> No issues found in policy: {policy['PolicyName']}")
    
    print(f"IAM check completed with {len(issues)} issues found.\n")
    return issues

# Function to detect publicly accessible S3 buckets
def check_aws_s3_buckets():
    """Detect publicly accessible S3 buckets by checking ACL, bucket policies, and block public access settings."""
    print("Checking for publicly accessible S3 buckets...")

    s3_client = boto3.client('s3')
    buckets = s3_client.list_buckets()['Buckets']

    print(f"Found {len(buckets)} buckets.")
    
    issues = []
    for bucket in buckets:
        bucket_name = bucket['Name']
        print(f"Checking bucket: {bucket_name}")

        # 1. Check Block Public Access Settings
        try:
            public_access_block = s3_client.get_bucket_policy_status(Bucket=bucket_name).get('PolicyStatus')
            if public_access_block and public_access_block.get('IsPublic') == True:
                issues.append(f"Bucket {bucket_name} has a public bucket policy.")
                print(f"  -> Public bucket policy detected: {bucket_name}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucketPolicy':
                print(f"  -> No bucket policy found for {bucket_name}.")
            else:
                print(f"  -> Could not retrieve public access block for {bucket_name}: {str(e)}")

        # 2. Check ACL settings
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    issues.append(f"Public S3 bucket detected via ACL: {bucket_name}")
                    print(f"  -> Public access via ACL detected: {bucket_name}")
                else:
                    print(f"  -> No public ACL detected for {bucket_name}")
        except Exception as e:
            print(f"  -> Could not retrieve ACL for {bucket_name}: {str(e)}")

        # 3. Check Bucket Policies
        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status['PolicyStatus']['IsPublic'] is True:
                issues.append(f"Public bucket policy detected on bucket: {bucket_name}")
                print(f"  -> Public bucket policy detected: {bucket_name}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucketPolicy':
                print(f"  -> No bucket policy set for {bucket_name}.")
            else:
                print(f"  -> Could not retrieve bucket policy status for {bucket_name}: {str(e)}")
    
    print(f"S3 bucket check completed with {len(issues)} issues found.\n")
    return issues

# Function to detect open security groups
def check_aws_security_groups():
    """Detect open security groups"""
    print("Checking for open security groups...")

    ec2_client = boto3.client('ec2')
    security_groups = ec2_client.describe_security_groups()['SecurityGroups']

    print(f"Found {len(security_groups)} security groups.")
    
    issues = []
    for sg in security_groups:
        print(f"Checking security group: {sg['GroupName']} ({sg['GroupId']})")
        for permission in sg['IpPermissions']:
            for ip_range in permission.get('IpRanges', []):
                # Check if the security group allows access from anywhere (0.0.0.0/0)
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    issues.append(f"Insecure Security Group detected: {sg['GroupName']} allows access from everywhere.")
                    print(f"  -> Insecure Security Group detected: {sg['GroupName']}")
                else:
                    print(f"  -> No public access detected for {sg['GroupName']}.")
    
    print(f"Security group check completed with {len(issues)} issues found.\n")
    return issues

# Function to send email alerts using SendGrid
def send_email_alert(subject, body, recipient_email):
    """Send real-time email alerts using SendGrid"""
    print("Preparing to send email alert...")
    
    message = Mail(
        from_email='nsasankhreddy@gmail.com',  # Replace with your verified email
        to_emails=recipient_email,  # Replace with the recipient email
        subject=subject,
        plain_text_content=body
    )
    try:
        sg = SendGridAPIClient('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')  # Your working key
        response = sg.send(message)
        print(f"Alert sent! Status code: {response.status_code}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

# Function to generate a report of AWS misconfigurations and send alerts
def generate_aws_security_report_and_send_alert():
    """Generate a report and send alerts if misconfigurations are detected"""
    print("Starting AWS security misconfiguration detection...\n")
    
    # Check IAM policies
    iam_issues = check_aws_iam()
    
    # Check S3 buckets
    s3_issues = check_aws_s3_buckets()
    
    # Check security groups
    sg_issues = check_aws_security_groups()

    # Combine all issues
    all_issues = iam_issues + s3_issues + sg_issues

    if all_issues:
        report = "\n".join(all_issues)
        print(f"Misconfigurations found: \n{report}")
        send_email_alert("AWS Misconfiguration Detected", report, "nandipatisasankhreddy@gmail.com")
        print("AWS security issues found and reported!")
    else:
        print("No AWS misconfigurations detected.")

if __name__ == "__main__":
    generate_aws_security_report_and_send_alert()
