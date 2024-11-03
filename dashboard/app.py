import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
import datetime

# Initialize the Flask application
app = Flask(__name__)

# Configure the SQLAlchemy database URI with the correct path
base_dir = os.path.abspath(os.path.dirname(__file__))
database_path = os.path.join(base_dir, '..', 'database.db')  # Navigate up one level to locate database.db
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Define the Issue model
class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    issue_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    remediation = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Route for the dashboard
@app.route('/')
def home():
    issues = Issue.query.order_by(Issue.timestamp.desc()).all()

    # Prepare data for chart
    dates = [issue.timestamp.date() for issue in issues]
    unique_dates = sorted(list(set(dates)))
    issue_counts = [dates.count(date) for date in unique_dates]

    return render_template('index.html', issues=issues, labels=unique_dates, data=issue_counts)

# Only run the app if this script is executed directly
if __name__ == '__main__':
    app.run(debug=True)
