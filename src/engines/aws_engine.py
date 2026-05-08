import boto3
import logging
import datetime
from datetime import timezone
from src.handlers.notifier import send_critical_alert
from src.handlers.remediator import revoke_public_access, secure_s3_bucket

logger = logging.getLogger(__name__)

# Initialize Clients
ec2 = boto3.client('ec2', region_name='us-east-1')
s3 = boto3.client('s3')
rds = boto3.client('rds', region_name='us-east-1')
iam = boto3.client('iam')
trail = boto3.client('cloudtrail', region_name='us-east-1')
gd = boto3.client('guardduty', region_name='us-east-1')
waf = boto3.client('wafv2', region_name='us-east-1')
config = boto3.client('config', region_name='us-east-1')
inspector = boto3.client('inspector2', region_name='us-east-1')
health = boto3.client('health', region_name='us-east-1')
secrets = boto3.client('secretsmanager', region_name='us-east-1')
lambda_client = boto3.client('lambda', region_name='us-east-1')
kms = boto3.client('kms', region_name='us-east-1')
accessanalyzer = boto3.client('accessanalyzer', region_name='us-east-1')
account = boto3.client('account', region_name='us-east-1')
r53_domains = boto3.client('route53domains', region_name='us-east-1')

def audit_security_groups(findings_list):
    """Scans and Heals EC2 Security Groups."""
    logger.info("Starting Security Group audit...")
    try:
        response = ec2.describe_security_groups()
        for group in response['SecurityGroups']:
            group_id = group['GroupId']
            for perm in group.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = perm.get('FromPort')
                        findings_list.put(f"EC2: {group_id} Port {port} is Public")
                        if port not in [80, 443]:
                            revoke_public_access(group_id, perm.get('IpProtocol'), port)
    except Exception as e:
        logger.error(f"EC2 Audit Failed: {str(e)}")

def audit_s3_buckets(findings_list):
    """Scans and Heals S3 Buckets."""
    logger.info("Starting S3 Bucket audit...")
    try:
        buckets = s3.list_buckets()['Buckets']
        for b in buckets:
            name = b['Name']
            try:
                s3.get_public_access_block(Bucket=name)
                logger.info(f"✅ S3: {name} is protected.")
            except:
                msg = f"S3: {name} is MISSING Public Access Block!"
                logger.warning(f"🚨 {msg}")
                findings_list.put(msg)
                # This is the "Healer" call
                secure_s3_bucket(name)
    except Exception as e:
        logger.error(f"S3 Audit Failed: {str(e)}")

def audit_rds_databases(findings_list):
    """Scans for RDS instances that are set to Publicly Accessible."""
    logger.info("Starting RDS Database audit...")
    try:
        
        instances = rds.describe_db_instances()['DBInstances']
        
        for db in instances:
            db_id = db['DBInstanceIdentifier']
            is_public = db['PubliclyAccessible']
            
            if is_public:
                msg = f"RDS: Database {db_id} is PUBLICLY ACCESSIBLE!"
                logger.warning(f"🚨 {msg}")
                findings_list.put(msg)
                # Note: In production, we don't 'Auto-Heal' RDS easily 
                # because it requires a reboot. We just Alert.
            else:
                logger.info(f"✅ RDS: {db_id} is secure (private).")
                
    except Exception as e:
        logger.error(f"RDS Audit Failed: {str(e)}")

def audit_iam_keys(findings_list):
    """Scans for IAM Access Keys older than 90 days."""
    logger.info("Starting IAM Access Key audit...")
    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            
            for key in keys:
                create_date = key['CreateDate']
                age_days = (datetime.datetime.now(timezone.utc) - create_date).days
                
                if age_days > 90:
                    msg = f"IAM: User {username} has a STALE key ({age_days} days old)!"
                    logger.warning(f"🚨 {msg}")
                    findings_list.put(msg)
                else:
                    logger.info(f"✅ IAM: {username} key is recent ({age_days} days).")
    except Exception as e:
        logger.error(f"IAM Audit Failed: {str(e)}")

def audit_cloudtrail(findings_list):
    """Ensures that at least one CloudTrail is active and logging."""
    logger.info("Starting CloudTrail audit...")
    try:
        response = trail.describe_trails()
        trails = response['trailList']
        
        if not trails:
            msg = "CLOUDTRAIL: No trails found! Your account has NO security logging."
            logger.warning(f"🚨 {msg}")
            findings_list.put(msg)
            return

        for t in trails:
            name = t['Name']
            status = trail.get_trail_status(Name=name)
            
            if not status['IsLogging']:
                msg = f"CLOUDTRAIL: Trail {name} exists but is NOT LOGGING!"
                logger.warning(f"🚨 {msg}")
                findings_list.put(msg)
            else:
                logger.info(f"✅ CloudTrail: {name} is active.")
                
    except Exception as e:
        logger.error(f"CloudTrail Audit Failed: {str(e)}")

def audit_vpc_flow_logs(findings_list):
    """Ensures that Network Flow Logging is enabled for all VPCs."""
    logger.info("Starting VPC Flow Log audit...")
    try:
       
        vpcs = ec2.describe_vpcs()['Vpcs']
        
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            
            flow_logs = ec2.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            )['FlowLogs']
            
            if not flow_logs:
                msg = f"NETWORK: VPC {vpc_id} has NO Flow Logs enabled! Traffic is invisible."
                logger.warning(f"🚨 {msg}")
                findings_list.put(msg)
            else:
                logger.info(f"✅ VPC: {vpc_id} network logging is active.")
                
    except Exception as e:
        logger.error(f"VPC Flow Log Audit Failed: {str(e)}")

def audit_guardduty(findings_list):
    """Ensures GuardDuty is enabled for the account."""
    logger.info("Starting GuardDuty audit...")
    try:
        detectors = gd.list_detectors()['DetectorIds']
        if not detectors:
            msg = "GUARDDUTY: Threat Detection is DISABLED!"
            logger.warning(f"🚨 {msg}")
            findings_list.put(msg)
        else:
            logger.info(f"✅ GuardDuty: Active on detector {detectors[0]}")
    except Exception as e:
        logger.error(f"GuardDuty Audit Failed: {str(e)}")

def audit_s3_encryption(findings_list):
    """Audits S3 buckets for Server-Side Encryption (SSE)."""
    try:
        buckets = s3.list_buckets()['Buckets']
        for b in buckets:
            name = b['Name']
            try:
                s3.get_bucket_encryption(Bucket=name)
            except:
                msg = f"S3: Bucket {name} is NOT encrypted at rest!"
                findings_list.put(msg)
    except Exception as e:
        logger.error(f"KMS Audit Failed: {str(e)}")

def audit_waf_logging(findings_list):
    """Checks if WAF Web ACLs have logging enabled."""
    logger.info("Starting WAF audit...")
    try:
        
        acls = waf.list_web_acls(Scope='REGIONAL')['WebACLs']
        
        if not acls:
            msg = "WAF: No Web ACLs found. Application is exposed to L7 attacks!"
            logger.warning(f"🚨 {msg}")
            findings_list.put(msg)
            return

        for acl in acls:
            name = acl['Name']
            arn = acl['ARN']
            try:
                
                waf.get_logging_configuration(ResourceArn=arn)
                logger.info(f"✅ WAF: {name} has logging enabled.")
            except:
                msg = f"WAF: {name} is active but has NO LOGGING enabled!"
                logger.warning(f"🚨 {msg}")
                findings_list.put(msg)
    except Exception as e:
        logger.error(f"WAF Audit Failed: {str(e)}")

def audit_config_recorder(findings_list):
    """Ensures the Configuration Recorder is running."""
    logger.info("Starting AWS Config audit...")
    try:
        recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
        if not recorders:
            msg = "CONFIG: No Configuration Recorder found!"
            findings_list.put(msg)
        else:
            for r in recorders:
                status = config.describe_configuration_recorder_status(
                    ConfigurationRecorderNames=[r['name']]
                )['ConfigurationRecorderStatus'][0]
                if not status['recording']:
                    msg = f"CONFIG: Recorder {r['name']} is NOT recording!"
                    findings_list.put(msg)
                else:
                    logger.info(f"✅ Config: {r['name']} is recording changes.")
    except Exception as e:
        logger.error(f"Config Audit Failed: {str(e)}")

def audit_inspector_coverage(findings_queue):
    """Checks if Inspector is active."""
    try:
        response = inspector.batch_get_account_status()
        statuses = response.get('accountStatuses', [])
        
        if not statuses or statuses[0].get('state', {}).get('status') != 'ENABLED':
            findings_queue.put("INSPECTOR: Vulnerability scanning is DISABLED!")
    except Exception:
        pass

def audit_ebs_encryption(findings_list):
    """Ensures that EBS Encryption by default is enabled for the region."""
    logger.info("Starting EBS Encryption audit...")
    try:
        
        is_enabled = ec2.get_ebs_encryption_by_default()['EbsEncryptionByDefault']
        
        if not is_enabled:
            msg = "EBS: Encryption by default is DISABLED for this region!"
            logger.warning(f"🚨 {msg}")
            findings_list.put(msg)
        else:
            logger.info("✅ EBS: Regional encryption by default is active.")
    except Exception as e:
        logger.error(f"EBS Audit Failed: {str(e)}")

def audit_aws_health(findings_list):
    """Checks for recent open health events affecting your AWS services."""
    logger.info("Starting AWS Health audit...")
    try:
        
        events = health.describe_events(filter={'eventStatusCodes': ['open']})['events']
        
        if events:
            msg = f"HEALTH: There are {len(events)} OPEN AWS service issues!"
            logger.warning(f"🚨 {msg}")
            findings_list.put(msg)
        else:
            logger.info("✅ Health: No active AWS service outages detected.")
    except Exception as e:
        
        logger.info("Health: API access restricted (Requires Business Support).")

def audit_secrets_rotation(findings_queue):
    """Ensures secrets have rotation enabled."""
    logger.info("Starting Secrets Manager audit...")
    try:
        response = secrets.list_secrets()
        for s in response['SecretList']:
            name = s['Name']
            if 'RotationEnabled' not in s or not s['RotationEnabled']:
                msg = f"SECRETS: {name} has rotation DISABLED!"
                findings_queue.put(msg)
            else:
                logger.info(f"✅ Secrets: {name} rotation is active.")
    except Exception as e:
        logger.error(f"Secrets Audit Failed: {str(e)}")

def audit_iam_password_policy(findings_queue):
    logger.info("Starting IAM Password Policy audit...")
    try:
        iam.get_account_password_policy()
        logger.info("✅ IAM: Password policy is set.")
    except:
        findings_queue.put("IAM: No account password policy defined!")

def audit_lambda_permissions(findings_queue):
    logger.info("Starting Lambda audit...")
    try:
        functions = lambda_client.list_functions()['Functions']
        for f in functions:
            try:
                policy = lambda_client.get_policy(FunctionName=f['FunctionName'])
                if 'Principal": "*"' in policy['Policy']:
                    findings_queue.put(f"LAMBDA: {f['FunctionName']} has PUBLIC permissions!")
            except:
                pass # No policy usually means private
    except Exception as e:
        logger.error(f"Lambda Audit Failed: {str(e)}")

def audit_kms_rotation(findings_queue):
    """Ensures Customer Master Keys (CMKs) have rotation enabled."""
    logger.info("Starting KMS audit...")
    try:
        keys = kms.list_keys()['Keys']
        for k in keys:
            kid = k['KeyId']
            # We add a 'Describe' check to see if it's a Customer Key
            metadata = kms.describe_key(KeyId=kid)['KeyMetadata']
            if metadata['KeyManager'] == 'CUSTOMER': 
                rotation = kms.get_key_rotation_status(KeyId=kid)
                if not rotation['KeyRotationEnabled']:
                    findings_queue.put(f"KMS: Key {kid} has rotation DISABLED!")
    except Exception as e:
        logger.error(f"KMS Audit Failed: {str(e)}")

def audit_access_analyzer(findings_queue):
    """Checks if IAM Access Analyzer is enabled."""
    logger.info("Starting Access Analyzer audit...")
    try:
        analyzers = accessanalyzer.list_analyzers()['analyzers']
        if not analyzers:
            findings_queue.put("IAM: Access Analyzer is DISABLED! No automated public access detection.")
        else:
            logger.info("✅ IAM: Access Analyzer is active.")
    except Exception as e:
        logger.error(f"Access Analyzer Audit Failed: {str(e)}")

def audit_security_contact(findings_queue):
    """Ensures a security contact is defined for the account."""
    logger.info("Starting Security Contact audit...")
    try:
        contact = account.get_alternate_contact(AlternateContactType='SECURITY')
        logger.info(f"✅ Account: Security contact is {contact['AlternateContact']['EmailAddress']}.")
    except:
        findings_queue.put("ACCOUNT: No Security Alternate Contact defined! Critical for incident response.")

def audit_route53_lock(findings_queue):
    """Checks if domains are locked to prevent unauthorized transfers."""
    logger.info("Starting Route 53 audit...")
    try:
        domains = r53_domains.list_domains()['Domains']
        for d in domains:
            name = d['DomainName']
            detail = r53_domains.get_domain_detail(DomainName=name)
            if not detail.get('TransferLock', True):
                findings_queue.put(f"ROUTE53: Domain {name} is NOT LOCKED!")
    except Exception as e:
        # Often fails if no domains are registered; we log and move on
        logger.info("Route53: No domains found in this account.")

def audit_guardduty_export(findings_list):
    """Ensures GuardDuty is exporting findings to a secure bucket."""
    logger.info("Starting GuardDuty Export audit...")
    try:
        detectors = gd.list_detectors()['DetectorIds']
        if not detectors:
            return
            
        for d_id in detectors:
            # Check if an export destination exists
            destinations = gd.list_publishing_destinations(DetectorId=d_id)['Destinations']
            if not destinations:
                msg = f"GUARDDUTY: Detector {d_id} is NOT exporting findings to S3!"
                findings_list.put(msg)
            else:
                logger.info(f"✅ GuardDuty: {d_id} export is configured.")
    except Exception as e:
        logger.error(f"GuardDuty Export Audit Failed: {str(e)}")

def remediate_ebs_encryption():
    """Staff Move: Automatically enables regional EBS encryption."""
    try:
        ec2.modify_ebs_default_encryption(Enabled=True)
        logger.info("🛠️ AUTO-HEAL: Regional EBS Encryption has been ENABLED.")
        return True
    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return False