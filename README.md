# ⚡ AWS Cloud Infrastructure Troubleshooting Toolkit

## Project Overview

This Python-based toolkit provides a suite of automated diagnostic and auditing scripts designed to help DevOps engineers, Cloud Engineers, and Support personnel quickly identify and resolve common infrastructure issues and unnecessary costs in an Amazon Web Services (AWS) environment.

The toolkit consolidates checks across four critical domains: **Connectivity, Security (IAM/S3),** and **Cost Optimization**.

## 🚀 Key Features

* **Network Diagnostics:** Pinpoints the exact layer (Security Group, NACL, or Route Table) causing EC2 connectivity issues.
* **Security Audits:** Scans S3 buckets for public exposure and identifies overly permissive ("God Mode") IAM policies.
* **Cost Savings:** Detects unattached, idle resources (EIPs, EBS volumes) that incur hidden charges.
* **Automated Reporting:** All findings are executed via a single wrapper script (`toolkit.py`) and saved into clean, actionable reports in the `reports/` directory.

## 🛠️ Requirements

* **Python 3.8+**
* **Boto3:** The AWS SDK for Python.
* **AWS CLI:** Must be installed and configured with valid credentials (`aws configure`).

### IAM Permissions

The IAM user or role executing this script requires **Read-Only** access to the following services to perform all checks:
* `ec2:Describe*` (For EC2 instances, SGs, NACLs, Route Tables, EIPs, EBS Volumes)
* `s3:ListAllMyBuckets`, `s3:Get*` (For bucket policies and access settings)
* `iam:List*`, `iam:Get*` (For IAM policies and users)
* `cloudwatch:GetMetricData` (If you choose to add more advanced metrics checks later)

## 📦 Setup and Installation

Follow these steps to set up the project locally:

1.  **Clone the repository:**
    ```sh
    git clone [Your-Repo-Link-Here]
    cd cloud-troubleshooting-toolkit
    ```

2.  **Create and activate a virtual environment:**
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    # .\venv\Scripts\activate   # On Windows
    ```

3.  **Install dependencies:**
    ```sh
    pip install boto3
    ```

4.  **Configure AWS Credentials:** Ensure your AWS CLI is set up.
    ```sh
    aws configure
    ```

## ⚙️ Configuration

Before running the toolkit, you must update the configuration in the main wrapper script, `toolkit.py`.

Open `toolkit.py` and replace the placeholder value for the EC2 connectivity check:

```python
# toolkit.py snippet

# !!! Configuration for Connectivity_Checker.py !!!
TEST_INSTANCE_ID = 'i-0a88b4214c12dcf0a'  # <-- **REPLACE THIS with a real Instance ID**
TEST_PROTOCOL = 'tcp'
TEST_PORT = '22'
