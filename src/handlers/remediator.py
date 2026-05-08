import boto3
import logging

logger = logging.getLogger(__name__)

# Clients for both services
ec2 = boto3.client('ec2', region_name='us-east-1')
s3 = boto3.client('s3')

def revoke_public_access(group_id, protocol, port):
    """Removes a 0.0.0.0/0 rule from an EC2 Security Group."""
    try:
        logger.warning(f"⚡ REMEDIATION: Revoking 0.0.0.0/0 on {group_id} port {port}")
        ec2.revoke_security_group_ingress(
            GroupId=group_id, IpProtocol=protocol,
            FromPort=port, ToPort=port, CidrIp='0.0.0.0/0'
        )
        logger.info(f"✅ Fixed Security Group: {group_id}")
        return True
    except Exception as e:
        logger.error(f"❌ EC2 Fix Failed: {str(e)}")
        return False

def secure_s3_bucket(bucket_name):
    """STAFF LEVEL: Automatically enables all Public Access Blocks for a bucket."""
    try:
        logger.warning(f"⚡ REMEDIATION: Securing S3 Bucket {bucket_name}")
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        logger.info(f"✅ Fixed S3 Bucket: {bucket_name}")
        return True
    except Exception as e:
        logger.error(f"❌ S3 Fix Failed: {str(e)}")
        return False