import os
from flask import Flask, render_template, redirect, url_for, flash, request
from models import db, Issue
from database_helpers import save_issue
from main import generate_aws_security_report_and_send_alert

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')  # Set secret key from environment or default

# Use DATABASE_URL for Railway, fallback to SQLite for local development
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database with the app
db.init_app(app)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    issues = Issue.query.order_by(Issue.Timestamp.desc()).all()
    print("Retrieved issues from database:", issues)  # Debug print for Railway logs
    
    dates = [issue.Timestamp.date() for issue in issues]
    unique_dates = sorted(list(set(dates)))
    issue_counts = [dates.count(date) for date in unique_dates]

    iam_score = int(request.args.get('iam_score', 100))
    s3_score = int(request.args.get('s3_score', 100))
    security_group_score = int(request.args.get('security_group_score', 100))

    return render_template(
        'index.html',
        issues=issues,
        labels=unique_dates,
        data=issue_counts,
        iam_score=iam_score,
        s3_score=s3_score,
        security_group_score=security_group_score
    )

@app.route('/run-tests', methods=['POST'])
def run_tests():
    try:
        issues_found = generate_aws_security_report_and_send_alert()
        print("Detected Issues:", issues_found)  # Debugging output for Railway logs

        for issue in issues_found:
            save_issue(issue['Type'], issue['Description'], issue.get('Remediation', ''))

        total_iam_issues = sum(1 for issue in issues_found if 'IAM' in issue['Type'])
        total_s3_issues = sum(1 for issue in issues_found if 'S3' in issue['Type'])
        total_security_group_issues = sum(1 for issue in issues_found if 'Security Group' in issue['Type'])

        iam_score = max(100 - total_iam_issues * 10, 0)
        s3_score = max(100 - total_s3_issues * 10, 0)
        security_group_score = max(100 - total_security_group_issues * 10, 0)

        print(f"IAM Score: {iam_score}, S3 Score: {s3_score}, Security Group Score: {security_group_score}")
        
        flash("Tests completed successfully! Report has been generated and sent via email.")
        return redirect(url_for('home', iam_score=iam_score, s3_score=s3_score, security_group_score=security_group_score))
    
    except Exception as e:
        flash(f"An error occurred while running tests: {str(e)}")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')
