"""
ETHIO-AI Defender - Defensive Threat Intelligence Service.

Provides safe static indicator lookups (IPs, domains, URLs, hashes).
Integrates with optional configured providers (VirusTotal, AbuseIPDB, AlienVault OTX).
Never fabricates threat intelligence data and cleanly reports unconfigured state when keys are absent.
"""

import re
import json
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from app.core.config import settings
from app.core.logger import logger


class ThreatIntelligenceService:
    """
    Manages external and local threat intelligence lookups for extracted IOCs.
    """

    @staticmethod
    def identify_indicator_type(indicator: str) -> str:
        """Determines if the indicator is an IP, Domain, URL, or Hash."""
        ind = indicator.strip()
        
        # Hashes
        if re.fullmatch(r"^[a-fA-F0-9]{64}$", ind):
            return "SHA256"
        if re.fullmatch(r"^[a-fA-F0-9]{40}$", ind):
            return "SHA1"
        if re.fullmatch(r"^[a-fA-F0-9]{32}$", ind):
            return "MD5"
        
        # IP Address (IPv4)
        if re.fullmatch(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ind):
            return "IP_ADDRESS"
            
        # URL
        if ind.startswith("http://") or ind.startswith("https://") or ind.startswith("ftp://"):
            return "URL"
            
        # Domain
        if re.fullmatch(r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$", ind):
            return "DOMAIN"
            
        return "GENERIC"

    @classmethod
    def lookup_indicator(cls, indicator: str) -> Dict[str, Any]:
        """
        Queries available configured threat intelligence services for reputation data.
        If no provider is configured, returns a clear unconfigured status without fabricating data.
        """
        indicator_clean = indicator.strip()
        ind_type = cls.identify_indicator_type(indicator_clean)
        
        # 1. Check if VirusTotal is configured
        if settings.VIRUSTOTAL_API_KEY:
            vt_result = cls._query_virustotal(indicator_clean, ind_type)
            if vt_result:
                return vt_result

        # 2. Check if AbuseIPDB is configured (for IP addresses)
        if settings.ABUSEIPDB_API_KEY and ind_type == "IP_ADDRESS":
            abuse_result = cls._query_abuseipdb(indicator_clean)
            if abuse_result:
                return abuse_result

        # 3. Check if AlienVault OTX is configured
        if settings.OTX_API_KEY:
            otx_result = cls._query_otx(indicator_clean, ind_type)
            if otx_result:
                return otx_result

        # 4. Default: No provider configured
        return {
            "configured": False,
            "indicator": indicator_clean,
            "indicator_type": ind_type,
            "provider": "Static Local Heuristics (External Unconfigured)",
            "message": "External threat intelligence is not configured. Configure VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, or OTX_API_KEY in environment variables to enable live external reputation queries.",
            "reputation": "UNCHECKED",
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 0,
            "confidence": 0.0,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": {
                "source": "Sample Static Evidence",
                "notes": "Observed in binary static artifacts. Requires dynamic analysis or external reputation service for definitive threat categorization."
            }
        }

    @classmethod
    def _query_virustotal(cls, indicator: str, ind_type: str) -> Optional[Dict[str, Any]]:
        """Queries VirusTotal v3 API."""
        try:
            headers = {
                "x-apikey": settings.VIRUSTOTAL_API_KEY,
                "Accept": "application/json",
                "User-Agent": f"ETHIO-AI-Defender/{settings.VERSION}"
            }
            
            if ind_type in ("SHA256", "SHA1", "MD5"):
                url = f"https://www.virustotal.com/api/v3/files/{indicator}"
            elif ind_type == "IP_ADDRESS":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
            elif ind_type == "DOMAIN":
                url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
            elif ind_type == "URL":
                import base64
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            else:
                return None

            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode())
                    attributes = payload.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    
                    rep = "CLEAN"
                    if malicious > 5:
                        rep = "MALICIOUS"
                    elif malicious > 0 or suspicious > 0:
                        rep = "SUSPICIOUS"

                    return {
                        "configured": True,
                        "indicator": indicator,
                        "indicator_type": ind_type,
                        "provider": "VirusTotal v3",
                        "reputation": rep,
                        "malicious_votes": malicious,
                        "suspicious_votes": suspicious,
                        "harmless_votes": harmless,
                        "confidence": min(1.0, (malicious * 0.1) + 0.5) if malicious > 0 else 0.8,
                        "last_checked": datetime.now(timezone.utc).isoformat(),
                        "details": attributes
                    }
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed for '{indicator}': {e}")
            return None

    @classmethod
    def _query_abuseipdb(cls, ip: str) -> Optional[Dict[str, Any]]:
        """Queries AbuseIPDB v2 API for IPv4 reputation."""
        try:
            headers = {
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
                "User-Agent": f"ETHIO-AI-Defender/{settings.VERSION}"
            }
            params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
            url = f"https://api.abuseipdb.com/api/v2/check?{params}"
            
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode())
                    data = payload.get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    
                    rep = "CLEAN"
                    if score >= 50:
                        rep = "MALICIOUS"
                    elif score >= 20:
                        rep = "SUSPICIOUS"

                    return {
                        "configured": True,
                        "indicator": ip,
                        "indicator_type": "IP_ADDRESS",
                        "provider": "AbuseIPDB v2",
                        "reputation": rep,
                        "malicious_votes": data.get("totalReports", 0),
                        "suspicious_votes": score,
                        "harmless_votes": 0,
                        "confidence": score / 100.0,
                        "last_checked": datetime.now(timezone.utc).isoformat(),
                        "details": data
                    }
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for '{ip}': {e}")
            return None

    @classmethod
    def _query_otx(cls, indicator: str, ind_type: str) -> Optional[Dict[str, Any]]:
        """Queries AlienVault OTX API."""
        try:
            headers = {
                "X-OTX-API-KEY": settings.OTX_API_KEY,
                "Accept": "application/json",
                "User-Agent": f"ETHIO-AI-Defender/{settings.VERSION}"
            }
            
            section = "general"
            if ind_type in ("SHA256", "SHA1", "MD5"):
                url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/{section}"
            elif ind_type == "IP_ADDRESS":
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/{section}"
            elif ind_type == "DOMAIN":
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/{section}"
            else:
                return None

            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode())
                    pulse_count = payload.get("pulse_info", {}).get("count", 0)
                    
                    rep = "CLEAN"
                    if pulse_count >= 3:
                        rep = "MALICIOUS"
                    elif pulse_count >= 1:
                        rep = "SUSPICIOUS"

                    return {
                        "configured": True,
                        "indicator": indicator,
                        "indicator_type": ind_type,
                        "provider": "AlienVault OTX",
                        "reputation": rep,
                        "malicious_votes": pulse_count,
                        "suspicious_votes": pulse_count,
                        "harmless_votes": 0,
                        "confidence": min(1.0, pulse_count * 0.2 + 0.4),
                        "last_checked": datetime.now(timezone.utc).isoformat(),
                        "details": payload
                    }
        except Exception as e:
            logger.warning(f"AlienVault OTX lookup failed for '{indicator}': {e}")
            return None


threat_intel_service = ThreatIntelligenceService()
