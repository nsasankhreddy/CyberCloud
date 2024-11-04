# CyberCloud - Security Misconfiguration Detection Tool

## Project Overview

**CyberCloud** is a Flask-based web application designed to identify and remediate security misconfigurations in Amazon Web Services Cloud Environment. It includes integrations for monitoring IAM policies, S3 bucket settings, and security groups, with added features for generating reports and sending real-time alerts for detected issues. Built with a security and compliance dashboard, CyberCloud provides users with detailed insights into their cloud security posture.

This README outlines the development and deployment process of CyberCloud, the challenges faced, and the solutions implemented to achieve a seamless setup on the Railway platform.

## Features

- **Security Checks**: Detects misconfigurations across IAM policies, S3 buckets, and security groups.
- **Alerts and Remediation**: Sends real-time alerts for detected issues and provides remediation suggestions.
- **Multi-Cloud Support**: Extends functionality to AWS, Azure, and GCP environments.
- **Deployment Platform**: Hosted on Railway for ease of access and scalability.

---

## Project Setup

### Initial Development

The application was initially developed locally using:
- **Python** for backend logic and security checks.
- **Flask** for the web interface.
- **SQLite** for lightweight data storage.

### Core Dependencies
The primary dependencies were added to `requirements.txt`, covering a wide range of libraries, from cloud SDKs (e.g., `boto3` for AWS) to data processing (e.g., `pandas`). Notable dependencies included:
  - **Flask** for the web application.
  - **Boto3** for AWS interactions.
  - **SQLAlchemy** for database management.
  - **Gunicorn** for deployment.

---

## Deployment on Railway

### Setting Up Railway Project

1. **Project Initialization**: Created a Railway project named "CyberCloud_Deploy" to host the application.
2. **Environment Variables**: Configured environment variables for AWS credentials, region, and other application secrets directly within Railway for security and flexibility.

### Challenges Faced & Solutions

#### 1. SQLite Database Support on Railway
   - **Challenge**: Hosting SQLite on a cloud environment can present issues, as it is a file-based database and can have limitations in production.
   - **Solution**: After assessing options, I moved forward with SQLite for simplicity, setting up paths within the Railway environment to ensure persistence.

#### 2. Credential Management and Multi-Cloud Configuration
   - **Challenge**: The application needed to interact with AWS, Azure, and GCP services using environment variables for credentials. Initially, AWS credentials were not recognized, causing issues with service connections.
   - **Solution**: Carefully ensured that all required credentials were set as Railway environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.). Additionally, created custom Boto3 clients for each AWS service (S3, IAM, EC2) to modularize service-specific access and handle credentials.

#### 3. Dependency Management
   - **Challenge**: The comprehensive list of dependencies caused build issues due to version conflicts and certain packages not installing correctly on Railway’s NIXPACKS builder.
   - **Solution**: Regularly refined `requirements.txt` by updating or downgrading specific libraries. Used simplified libraries where possible to reduce dependency weight and resolved conflicts by testing individual installs locally before committing them to Railway.

#### 4. Runtime and Configuration
   - **Challenge**: Railway’s runtime needed to support the Gunicorn server, which required specifying start commands.
   - **Solution**: Configured a `Procfile` to specify Gunicorn as the WSGI server (`web: gunicorn app:app`) and adjusted `railway.json` to define the start command and deployment settings for compatibility with Railway’s platform.

---

## Key Configuration Files

### `railway.json`
The `railway.json` file was crafted to optimize Railway's build and deployment process. Key configurations included specifying the builder, runtime settings, start command, and restart policies.

### `Procfile`
To ensure proper startup with Gunicorn, I used the following `Procfile`:

```plaintext
web: gunicorn app:app
```

## .env for Local Testing
Locally, I configured environment variables using .env for AWS credentials and other secrets, ensuring consistent environment management across local and Railway environments.

## Lessons Learned
Effective Dependency Management: Keeping requirements.txt clean and minimal is crucial to avoid installation and compatibility issues during deployment.

Thorough Testing: Testing each service (e.g., S3, IAM) individually during the initial stages helps in isolating issues with environment variables and permissions, which can save time and debugging effort.

Robust Environment Configuration: Managing credentials securely and correctly is key to seamless deployment. Using environment variables was instrumental in ensuring secure, consistent access to required services across development and production.

Railway Deployment Optimization: Railway's NIXPACKS builder and railway.json configurations provide flexibility but require careful setup. Setting custom start commands and policies in the railway.json file contributed significantly to maintaining application stability and reliability.

## Conclusion
Deploying CyberCloud on Railway was a journey filled with learning and troubleshooting. By carefully managing dependencies, handling environment configurations, and optimizing for Railway’s platform, I successfully deployed the application, making it production-ready and resilient. CyberCloud now serves as a practical tool for monitoring cloud security across AWS, Azure, and GCP environments.
This journey not only highlighted the importance of precise configuration management but also reinforced best practices for cloud-based deployment and security monitoring.

![image](https://github.com/user-attachments/assets/78998cdd-4f27-49c5-a8ca-347b6d92f6ad)
![image](https://github.com/user-attachments/assets/eac94239-0ea9-4d6d-9176-afeb4a93596d)
![image](https://github.com/user-attachments/assets/17b2a190-17f6-4da3-93c3-44fd8e508c84)
![image](https://github.com/user-attachments/assets/8dc1ad0b-411a-40ed-b7be-ce1fcb73e7c5)

###### Demo Link: https://web-production-7ad1f.up.railway.app/
