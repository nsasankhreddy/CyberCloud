from models import db, Issue
from flask import current_app

def save_issue(issue_type, description, remediation):
    """Save a new issue to the database."""
    with current_app.app_context():
        new_issue = Issue(
            Issue_type=issue_type,     # Make sure this matches the field name exactly
            Description=description,
            Remediation=remediation
        )
        db.session.add(new_issue)
        db.session.commit()
        print(f"Saved issue to database: {new_issue}")
