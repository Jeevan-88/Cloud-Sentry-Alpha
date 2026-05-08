import logging
from google.cloud import storage
from googleapiclient import discovery

logger = logging.getLogger(__name__)

def audit_gcp_storage(findings_list):
    """Audits GCP Buckets for public access."""
    logger.info("Starting GCP Storage audit...")
    try:
        client = storage.Client()
        buckets = list(client.list_buckets())
        for bucket in buckets:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            
            for binding in policy.bindings:
                if "allUsers" in binding["members"]:
                    msg = f"GCP: Bucket {bucket.name} is PUBLIC!"
                    findings_list.put(msg)
    except Exception as e:
        logger.error(f"GCP Audit Failed: {str(e)}")

def audit_gcp_sql_public(findings_list):
    """Checks if GCP SQL instances are exposed via Public IPs."""
    logger.info("Starting GCP SQL audit...")
    try:
        service = discovery.build('sqladmin', 'v1beta4')
        # Using your Project ID from the gcloud command
        req = service.instances().list(project="project-fe44efaf-a7af-401d-a7d")
        resp = req.execute()
        
        for instance in resp.get('items', []):
            ip_config = instance.get('settings', {}).get('ipConfiguration', {})
            if ip_config.get('ipv4Enabled'):
                msg = f"GCP_SQL: Instance {instance['name']} has a Public IP enabled!"
                findings_list.put(msg)
            else:
                logger.info(f"✅ GCP_SQL: {instance['name']} is private.")
    except Exception as e:
        logger.error(f"GCP SQL Audit Failed: {str(e)}")