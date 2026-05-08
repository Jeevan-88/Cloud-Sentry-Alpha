import boto3
import logging

logger = logging.getLogger(__name__)
sns = boto3.client('sns', region_name='us-east-1')


TOPIC_ARN = "arn:aws:sns:us-east-1:462457676536:CloudSentry-Sentinel-Alerts"

def send_critical_alert(service_name, issue_detail):
    """Formats and sends a production-grade alert."""
    message = f"🚨 CRITICAL VULNERABILITY\nService: {service_name}\nDetail: {issue_detail}"
    
    try:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Message=message,
            Subject=f"Cloud-Sentry Alert: {service_name}"
        )
        logger.info(f"Alert sent successfully for {service_name}")
    except Exception as e:
        logger.error(f"Failed to send alert: {str(e)}")