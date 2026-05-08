import logging
import os
import queue
from concurrent.futures import ThreadPoolExecutor
from src.handlers.remediator import heal_ebs_encryption, heal_iam_password_policy, heal_access_analyzer
from src.engines.aws_engine import (
    audit_security_groups, 
    audit_s3_buckets, 
    audit_rds_databases, 
    audit_iam_keys,
    audit_cloudtrail,
    audit_vpc_flow_logs,
    audit_guardduty,
    audit_s3_encryption,
    audit_waf_logging,
    audit_config_recorder,
    audit_inspector_coverage,
    audit_ebs_encryption,
    audit_aws_health,
    audit_secrets_rotation,
    audit_lambda_permissions,
    audit_iam_password_policy,
    audit_kms_rotation,
    audit_access_analyzer,
    audit_security_contact,
    audit_route53_lock,
    audit_guardduty_export,
    remediate_ebs_encryption
)

from src.engines.gcp_engine import (
    audit_gcp_storage,
    audit_gcp_sql_public
)
from src.engines.azure_engine import (
    audit_azure_sql_firewall,
    audit_azure_nsg,
    audit_azure_storage
)
# Production Logging Format
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_sentinel():
    logger.info("🚀 Cloud-Sentry-Alpha: Initializing Master Multi-Service Audit...")
    master_findings = []
    findings_queue = queue.Queue()
    # heal_ebs_encryption()
    # heal_iam_password_policy()
    # heal_access_analyzer()
    
    audit_tasks = [
        # AWS 
        audit_security_groups, audit_s3_buckets, audit_rds_databases, 
        audit_iam_keys, audit_cloudtrail, audit_vpc_flow_logs, 
        audit_guardduty, audit_s3_encryption, audit_waf_logging, 
        audit_config_recorder, audit_inspector_coverage, 
        audit_ebs_encryption, audit_aws_health, audit_secrets_rotation,
        audit_lambda_permissions, audit_iam_password_policy, 
        audit_kms_rotation, audit_access_analyzer, 
        audit_security_contact, audit_route53_lock, audit_guardduty_export,
        remediate_ebs_encryption,
        
        # GCP (
        audit_gcp_storage, audit_gcp_sql_public,
        
        # Azure 
        audit_azure_storage, audit_azure_sql_firewall, audit_azure_nsg

    ]

    # 2. Execute in Parallel 
    with ThreadPoolExecutor(max_workers=15) as executor:
        for task in audit_tasks:
            # We pass the queue instead of the list
            executor.submit(task, findings_queue)
            
    master_findings = list(findings_queue.queue)
    # 3. Security Scoring Logic 
    issues_found = len(master_findings)
    
    security_score = max(0, 100 - (len(master_findings) * 4))
    
    logger.info("------------------------------------------")
    logger.info(f"📊 FINAL SECURITY SCORE: {security_score}/100")
    logger.info("------------------------------------------")

    if master_findings:
        logger.info(f"✅ Audit Complete. Found {issues_found} total issues.")
        for issue in master_findings:
            logger.warning(f"  - {issue}")
    else:
        logger.info("✅ Audit Complete. No high-risk vulnerabilities detected.")

if __name__ == "__main__":
    run_sentinel()