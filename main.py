import os
from compliance_checks import run_compliance_checks
from misconfiguration_checks import check_aws_iam, check_aws_s3_buckets, check_aws_security_groups
from email_alert import send_email_alert
from utils.logger import get_logger

logger = get_logger(__name__)

def generate_aws_security_report_and_send_alert():
    """Generate a report including compliance and misconfiguration checks with remediation suggestions."""
    logger.info("Starting AWS security misconfiguration detection and compliance audit...\n")
    
    # Run misconfiguration checks
    iam_issues = check_aws_iam()
    s3_issues = check_aws_s3_buckets()
    sg_issues = check_aws_security_groups()
    
    # Run compliance checks
    compliance_issues = run_compliance_checks()
    
    # Combine all issues
    all_issues = iam_issues + s3_issues + sg_issues + compliance_issues

    if all_issues:
        report = "\n".join(f"{issue[0]}\nSuggested Remediation: {issue[1]}" for issue in all_issues)
        logger.info(f"Misconfigurations and compliance issues found: \n{report}")
        send_email_alert("AWS Security & Compliance Issues Detected", report, os.getenv('RECIPIENT_EMAIL'))
        logger.info("AWS security issues found and reported!")
    else:
        logger.info("No AWS misconfigurations or compliance issues detected.")

if __name__ == "__main__":
    generate_aws_security_report_and_send_alert()
