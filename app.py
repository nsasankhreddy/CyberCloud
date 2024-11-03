import os
import requests
from flask import Flask, render_template, redirect, url_for, flash, request, session
from authlib.integrations.flask_client import OAuth
from models import db, Issue
from database_helpers import save_issue
from main import generate_aws_security_report_and_send_alert

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
with app.app_context():
    db.create_all()

# Configure OAuth with authlib
oauth = OAuth(app)
cognito = oauth.register(
    name='cybercloud',
    client_id='YOUR_CLIENT_ID',
    client_secret='YOUR_CLIENT_SECRET',
    server_metadata_url='https://cybercloud-dashboard.auth.us-east-1.amazoncognito.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile'}
)

@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return cognito.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    token = cognito.authorize_access_token()
    if token is None:
        flash("Access denied or no response from Cognito.", "error")
        return redirect(url_for('home'))

    session['access_token'] = token['access_token']
    flash("You have successfully logged in.", "success")
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('home'))

@app.route('/')
def home():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    issues = Issue.query.order_by(Issue.Timestamp.desc()).all()
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
    if 'access_token' not in session:
        return redirect(url_for('login'))

    try:
        access_token = session['access_token']
        issues_found = generate_aws_security_report_and_send_alert(access_token)
        
        for issue in issues_found:
            save_issue(issue['Type'], issue['Description'], issue.get('Remediation', ''))
        
        total_iam_issues = sum(1 for issue in issues_found if 'IAM' in issue['Type'])
        total_s3_issues = sum(1 for issue in issues_found if 'S3' in issue['Type'])
        total_security_group_issues = sum(1 for issue in issues_found if 'Security Group' in issue['Type'])
        
        iam_score = max(100 - total_iam_issues * 10, 0)
        s3_score = max(100 - total_s3_issues * 10, 0)
        security_group_score = max(100 - total_security_group_issues * 10, 0)

        flash("Tests completed successfully! Report has been generated and sent via email.")
        return redirect(url_for('home', iam_score=iam_score, s3_score=s3_score, security_group_score=security_group_score))
    
    except Exception as e:
        flash(f"An error occurred while running tests: {str(e)}")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
