import os
from flask import Flask, render_template, redirect, url_for, flash, request
from models import db, Issue  # Import from models
from database_helpers import save_issue  # Import save_issue from database_helpers
from main import generate_aws_security_report_and_send_alert  # Import function to run security checks

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure the SQLAlchemy database URI
base_dir = os.path.abspath(os.path.dirname(__file__))
database_path = os.path.join(base_dir, 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database with the app
db.init_app(app)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    issues = Issue.query.order_by(Issue.Timestamp.desc()).all()
    
    # Debugging print statements to confirm data retrieval
    print("Retrieved issues from database:", issues)
    
    # Extract dates and calculate the issue count per date
    dates = [issue.Timestamp.date() for issue in issues]
    unique_dates = sorted(list(set(dates)))
    issue_counts = [dates.count(date) for date in unique_dates]

    # Debug prints for unique dates and issue counts
    print("Unique dates:", unique_dates)
    print("Issue counts:", issue_counts)

    # Retrieve scores from query parameters or set default to 100
    iam_score = int(request.args.get('iam_score', 100))
    s3_score = int(request.args.get('s3_score', 100))
    security_group_score = int(request.args.get('security_group_score', 100))

    return render_template(
        'index.html',
        issues=issues,
        labels=unique_dates,  # Dates for the X-axis of the trend chart
        data=issue_counts,     # Issue counts for the Y-axis of the trend chart
        iam_score=iam_score,
        s3_score=s3_score,
        security_group_score=security_group_score
    )

@app.route('/run-tests', methods=['POST'])
def run_tests():
    """Route to run the security tests and save results in the database."""
    try:
        # Run security checks and retrieve any issues found
        issues_found = generate_aws_security_report_and_send_alert()

        # Debug print to confirm issues_found content
        print("Detected Issues:", issues_found)

        # Save each issue in the database
        for issue in issues_found:
            save_issue(issue['Type'], issue['Description'], issue.get('Remediation', ''))
        
        # Calculate the scores based on the issues found
        total_iam_issues = sum(1 for issue in issues_found if 'IAM' in issue['Type'])
        total_s3_issues = sum(1 for issue in issues_found if 'S3' in issue['Type'])
        total_security_group_issues = sum(1 for issue in issues_found if 'Security Group' in issue['Type'])
        
        iam_score = max(100 - total_iam_issues * 10, 0)
        s3_score = max(100 - total_s3_issues * 10, 0)
        security_group_score = max(100 - total_security_group_issues * 10, 0)

        # Debug print to confirm calculated scores
        print(f"IAM Score: {iam_score}, S3 Score: {s3_score}, Security Group Score: {security_group_score}")
        
        flash("Tests completed successfully! Report has been generated and sent via email.")
        
        # Redirect back to the home page with scores as parameters
        return redirect(url_for('home', iam_score=iam_score, s3_score=s3_score, security_group_score=security_group_score))
    
    except Exception as e:
        flash(f"An error occurred while running tests: {str(e)}")
        return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
