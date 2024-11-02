from compliance_checks import run_compliance_checks
from misconfiguration_checks import check_aws_iam, check_aws_s3_buckets, check_aws_security_groups
from email_alert import send_email_alert

def generate_aws_security_report_and_send_alert():
    """Generate a report including compliance checks and send alerts if misconfigurations are detected."""
    print("Starting AWS security misconfiguration detection and compliance audit...\n")
    
    # Run misconfiguration checks
    iam_issues = check_aws_iam()
    s3_issues = check_aws_s3_buckets()
    sg_issues = check_aws_security_groups()
    
    # Run compliance checks
    compliance_issues = run_compliance_checks()
    
    # Combine all issues
    all_issues = iam_issues + s3_issues + sg_issues + compliance_issues

    if all_issues:
        report = "\n".join(all_issues)
        print(f"Misconfigurations and compliance issues found: \n{report}")
        send_email_alert("AWS Security & Compliance Issues Detected", report, "nandipatisasankhreddy@gmail.com")
        print("AWS security issues found and reported!")
    else:
        print("No AWS misconfigurations or compliance issues detected.")

if __name__ == "__main__":
    generate_aws_security_report_and_send_alert()
