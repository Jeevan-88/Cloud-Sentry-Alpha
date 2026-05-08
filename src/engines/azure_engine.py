import logging
from azure.mgmt.network import NetworkManagementClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.sql import SqlManagementClient
logger = logging.getLogger(__name__)

def audit_azure_storage(findings_queue):
    """Placeholder for Azure Storage Audit."""
    logger.info("Starting Azure Storage audit... (Auth pending)")
    # We won't add logic yet until you've logged in via the CLI
    pass

def audit_azure_nsg(findings_queue):
    """Audits Azure NSGs for wide-open management ports."""
    logger.info("Starting Azure NSG audit...")
    try:
        credential = DefaultAzureCredential()
        # Using your Subscription ID from the terminal output
        network_client = NetworkManagementClient(credential, "dc2daffc-f283-4e35-8431-99c88c9cedcf")
        
        # NSGs are tied to Resource Groups, so we list all in the sub
        nsgs = network_client.network_security_groups.list_all()
        for nsg in nsgs:
            for rule in nsg.security_rules:
                # Check for 'Inbound', 'Allow', and 'Any' source
                if rule.access == "Allow" and rule.direction == "Inbound":
                    if rule.source_address_prefix == "*" and (rule.destination_port_range in ["22", "3389", "*"]):
                        msg = f"AZURE: NSG {nsg.name} Rule {rule.name} is PUBLICly exposed!"
                        findings_queue.put(msg)
    except Exception as e:
        logger.error(f"Azure NSG Audit Failed: {str(e)}")

def audit_azure_sql_firewall(findings_list):
    """Audits Azure SQL Firewall for overly permissive rules."""
    logger.info("Starting Azure SQL audit...")
    try:
        credential = DefaultAzureCredential()
        client = SqlManagementClient(credential, "dc2daffc-f283-4e35-8431-99c88c9cedcf")
        
        # This lists all SQL servers in your subscription
        servers = client.servers.list()
        for server in servers:
            rules = client.firewall_rules.list_by_server(server.resource_group, server.name)
            for rule in rules:
                if rule.start_ip_address == "0.0.0.0":
                    msg = f"AZURE_SQL: Server {server.name} allows ALL Azure traffic!"
                    findings_list.put(msg)
    except Exception as e:
        logger.error(f"Azure SQL Audit Failed: {str(e)}")