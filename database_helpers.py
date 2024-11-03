from dashboard.app import db, Issue, app  # Import the app to use app context

def save_issue(issue_type, description, remediation):
    """Save a new issue to the database."""
    with app.app_context():  # Use the app context to allow db access
        new_issue = Issue(
            issue_type=issue_type,
            description=description,
            remediation=remediation
        )
        db.session.add(new_issue)
        db.session.commit()
