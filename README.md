# CyberCloud - Security Misconfiguration Detection Tool

## Project Overview
**CyberCloud** is a Flask-based web application designed to identify and remediate security misconfigurations in Amazon Web Services Cloud Environment. It includes integrations for monitoring IAM policies, S3 bucket settings, and security groups, with added features for generating reports and sending real-time alerts for detected issues. Built with a security and compliance dashboard, CyberCloud provides users with detailed insights into their cloud security posture.

## Problem Statement
Cloud environments often face security vulnerabilities due to misconfigurations, posing significant risks to organizations. Identifying and addressing these misconfigurations promptly is critical to maintaining a secure cloud infrastructure. **CyberCloud** addresses this need by providing a comprehensive tool to detect, report, and suggest remediations for cloud security issues.

## Technology Stack
- **Programming Language**: Python
- **Frameworks**: Flask
- **Cloud SDKs**: Boto3 (AWS)
- **Database**: SQLite
- **Deployment Tools**: Railway, Gunicorn
- **Other Tools**: SQLAlchemy, Pandas

## Features
- **Security Checks**: Detects misconfigurations across IAM policies, S3 buckets, and security groups.
- **Alerts and Remediation**: Sends real-time alerts for detected issues and provides remediation suggestions.
- **Multi-Cloud Support**: Extends functionality to AWS, Azure, and GCP environments.
- **Deployment Platform**: Hosted on Railway for ease of access and scalability.

## Project Setup
### Initial Development
The application was initially developed locally using Python for backend logic and Flask for the web interface. SQLite was chosen for lightweight data storage during initial development.

### Core Dependencies
Key dependencies in `requirements.txt` include:
- **Flask**: Web application framework
- **Boto3**: AWS SDK for Python
- **SQLAlchemy**: Database management
- **Gunicorn**: WSGI server for deployment

## Usage Guide
1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/cybercloud.git
   ```
2. **Navigate to the project directory**:
   ```bash
   cd cybercloud
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Set up environment variables**:
   Create a `.env` file for local testing and configure AWS credentials and other secrets.
5. **Run the application**:
   ```bash
   flask run
   ```

## Architecture Overview
The project structure is modular, consisting of separate components for:
- **Cloud SDK interactions**: Custom Boto3 clients for different AWS services.
- **Web Interface**: Flask routes handling user interactions.
- **Database Management**: Handled by SQLAlchemy for persistent data storage.

## Project Structure
```
cybercloud/
|-- app.py
|-- templates/
|-- static/
|-- models.py
|-- services/
|-- utils/
|-- requirements.txt
|-- Procfile
|-- railway.json
|-- .env
```

## Deployment on Railway
### Setting Up Railway Project
1. **Project Initialization**: Created a Railway project named "CyberCloud_Deploy".
2. **Environment Variables**: Configured necessary variables (e.g., `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).

### Key Configuration Files
- **`railway.json`**: Contains build and deployment settings for Railway.
- **`Procfile`**:
  ```
  web: gunicorn app:app
  ```

## Challenges Faced & Solutions
### 1. SQLite Database Support on Railway
- **Challenge**: File-based limitations in cloud environments.
- **Solution**: Configured paths in Railway for database persistence.

### 2. Credential Management and Multi-Cloud Configuration
- **Challenge**: Managing and securely accessing cloud credentials.
- **Solution**: Used Railway environment variables and modularized Boto3 client creation.

### 3. Dependency Management
- **Challenge**: Build issues with version conflicts.
- **Solution**: Regularly refined `requirements.txt` and tested individual installations locally.

### 4. Runtime and Configuration
- **Challenge**: Configuring Railway’s runtime to support Gunicorn.
- **Solution**: Used a `Procfile` and configured Railway settings for a stable deployment.

## Lessons Learned
- **Effective Dependency Management**: Maintaining a minimal and conflict-free `requirements.txt`.
- **Thorough Testing**: Isolating services during initial stages to identify environment issues.
- **Robust Environment Configuration**: Secure and consistent use of environment variables.
- **Deployment Optimization**: Importance of custom start commands and policies in `railway.json`.

## Future Enhancements
- **Advanced Reporting**: Adding deeper insights into detected security issues.
- **User Management**: Implementing role-based access.
- **Expanded Multi-Cloud Support**: Full integration with Azure and GCP.

## Contact Information
**Author**: Sasankh Reddy Nandipati  
**Email**: [nandipatisasankhreddy@gmail.com](mailto:nandipatisasankhreddy@gmail.com)  
**LinkedIn**: [Sasankh Reddy](https://www.linkedin.com/in/sasankh-reddy-nandipati-bb38912a0/)

## Conclusion
Deploying **CyberCloud** on Railway required overcoming challenges related to dependency management, environment configuration, and runtime stability. This project serves as a practical demonstration of building, deploying, and maintaining a cloud security tool, emphasizing best practices in cloud development and security monitoring.

---

**Demo Link**: [CyberCloud Live Demo](https://web-production-7ad1f.up.railway.app/)

