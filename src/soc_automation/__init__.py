"""SOC Automation module - Wazuh, TheHive, Shuffle, VirusTotal integration."""
from .wazuh_integration import WazuhClient
from .thehive_client import TheHiveClient
from .shuffle_webhook import ShuffleWebhook
from .virustotal_client import VirusTotalClient

__all__ = ["WazuhClient", "TheHiveClient", "ShuffleWebhook", "VirusTotalClient"]
