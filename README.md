# 🛡️ Cloud-Sentry-Alpha v1.0.0

**Sovereign Multi-Cloud Security & Governance Orchestrator**

Cloud-Sentry-Alpha is a high-performance **Cloud Security Posture Management (CSPM)** engine designed for the rapid identification and auto-remediation of security gaps across **AWS, GCP, and Azure**.

## 🚀 The Engineering Challenge
Standard security audits are often sequential and slow. Cloud-Sentry-Alpha solves this through **Asynchronous Concurrency**, utilizing Python's `ThreadPoolExecutor` to perform a 25-service deep audit in **under 6 seconds**.

### 🛠️ Key Architectural Features
* **Multi-Cloud Integration:** Unified SDK handling for Boto3 (AWS), Google Cloud SDK, and Azure Management SDK.
* **Concurrent Execution:** Orchestrated multi-threading with a **Thread-Safe Queue** to prevent Race Conditions during finding aggregation.
* **Automated Remediation:** Built-in "Healer" modules that programmatically close security gaps (e.g., revoking public SSH access, enabling EBS encryption).
* **Dynamic Posture Scoring:** A weighted algorithm that provides an immediate health score of the infrastructure.

## 📊 25-Service Audit Scope
* **AWS:** IAM (Keys, Policy, MFA), S3 (Public Block, Encryption), RDS, GuardDuty, WAFv2, KMS, Lambda, etc.
* **GCP:** Cloud Storage, Cloud SQL Public IP Audit, Firewall Rules.
* **Azure:** Network Security Groups (NSG), Storage Account Access, SQL Firewall.

## 📦 Getting Started
1. **Clone the Repo:** `git clone https://github.com/Jeevan-88/Cloud-Sentry-Alpha.git`
2. **Setup Environment:** `pip install -r requirements.txt`
3. **Authenticate:** Run `aws configure`, `gcloud auth`, and `az login`.
4. **Launch Sentry:** `python3 src/main.py`