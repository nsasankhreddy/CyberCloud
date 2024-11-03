# models.py
from flask_sqlalchemy import SQLAlchemy
import datetime

# Initialize the SQLAlchemy object
db = SQLAlchemy()

# Define the Issue model
class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Issue_type = db.Column(db.String(50), nullable=False)
    Description = db.Column(db.String(255), nullable=False)
    Remediation = db.Column(db.String(255), nullable=True)
    Timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
