"""
GitHub REST API connector for Bronze layer ingestion.
Fetches deployments, releases, workflow runs, and security data.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

from src.bronze.base_connector import BaseConnector
from src.config.settings import settings

logger = logging.getLogger(__name__)


class GitHubConnector(BaseConnector):
    """Connector for GitHub REST API."""
    
    def __init__(
        self,
        token: Optional[str] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize GitHub connector.
        
        Args:
            token: GitHub personal access token or GitHub App token
            owner: Default repository owner/organization
            repo: Default repository name
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        super().__init__(
            name="GitHub",
            base_url="https://api.github.com",
            api_key=token or settings.github_token,
            timeout=timeout,
            max_retries=max_retries,
        )
        
        self.owner = owner
        self.repo = repo
        
        if not self.api_key:
            raise ValueError("GitHub token is required")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for GitHub API requests."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    
    async def health_check(self) -> bool:
        """
        Check if the GitHub API is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Check rate limit endpoint
            await self._make_request("GET", "/rate_limit")
            logger.info(f"{self.name} health check passed")
            return True
        except Exception as e:
            logger.error(f"{self.name} health check failed: {e}")
            return False
    
    async def fetch(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Fetch events from GitHub.
        
        Args:
            start_time: Start of time range (default: last hour)
            end_time: End of time range (default: now)
            **kwargs: Additional parameters:
                - owner: Repository owner (required if not set in __init__)
                - repo: Repository name (required if not set in __init__)
                - fetch_deployments: Fetch deployments (default: True)
                - fetch_releases: Fetch releases (default: True)
                - fetch_workflow_runs: Fetch GitHub Actions workflow runs (default: True)
                - fetch_security_alerts: Fetch security alerts (default: False)
        
        Returns:
            List of raw event dictionaries in Bronze format
        """
        if start_time is None or end_time is None:
            start_time, end_time = self._get_default_time_range()
        
        owner = kwargs.get("owner", self.owner)
        repo = kwargs.get("repo", self.repo)
        
        if not owner or not repo:
            raise ValueError("owner and repo must be specified")
        
        all_events = []
        
        # Fetch deployments
        if kwargs.get("fetch_deployments", True):
            deployments = await self._fetch_deployments(owner, repo, start_time, end_time)
            all_events.extend(deployments)
        
        # Fetch releases
        if kwargs.get("fetch_releases", True):
            releases = await self._fetch_releases(owner, repo, start_time, end_time)
            all_events.extend(releases)
        
        # Fetch workflow runs
        if kwargs.get("fetch_workflow_runs", True):
            workflow_runs = await self._fetch_workflow_runs(owner, repo, start_time, end_time)
            all_events.extend(workflow_runs)
        
        # Fetch security alerts (requires appropriate permissions)
        if kwargs.get("fetch_security_alerts", False):
            security_alerts = await self._fetch_security_alerts(owner, repo)
            all_events.extend(security_alerts)
        
        logger.info(f"Fetched {len(all_events)} events from {self.name}")
        return all_events
    
    async def _fetch_deployments(
        self,
        owner: str,
        repo: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch deployments from GitHub."""
        try:
            query_params = {
                "per_page": 100,
            }
            
            response = await self._make_request(
                "GET",
                f"/repos/{owner}/{repo}/deployments",
                params=query_params
            )
            
            # Filter by time range
            deployments = [
                d for d in response
                if self._is_within_range(d.get("created_at", ""), start_time, end_time)
            ]
            
            # Fetch deployment statuses
            result = []
            for deployment in deployments:
                deployment_id = deployment.get("id")
                statuses = await self._fetch_deployment_statuses(owner, repo, deployment_id)
                deployment["statuses"] = statuses
                result.append(self._transform_deployment(deployment))
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to fetch deployments: {e}")
            return []
    
    async def _fetch_deployment_statuses(
        self,
        owner: str,
        repo: str,
        deployment_id: int
    ) -> List[Dict[str, Any]]:
        """Fetch deployment statuses for a deployment."""
        try:
            response = await self._make_request(
                "GET",
                f"/repos/{owner}/{repo}/deployments/{deployment_id}/statuses",
                params={"per_page": 100}
            )
            return response
        except Exception as e:
            logger.error(f"Failed to fetch deployment statuses: {e}")
            return []
    
    async def _fetch_releases(
        self,
        owner: str,
        repo: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch releases from GitHub."""
        try:
            query_params = {
                "per_page": 100,
            }
            
            response = await self._make_request(
                "GET",
                f"/repos/{owner}/{repo}/releases",
                params=query_params
            )
            
            # Filter by time range
            releases = [
                r for r in response
                if self._is_within_range(r.get("published_at", ""), start_time, end_time)
            ]
            
            return [self._transform_release(r) for r in releases]
        
        except Exception as e:
            logger.error(f"Failed to fetch releases: {e}")
            return []
    
    async def _fetch_workflow_runs(
        self,
        owner: str,
        repo: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch GitHub Actions workflow runs."""
        try:
            query_params = {
                "per_page": 100,
                "created": f">={start_time.strftime('%Y-%m-%d')}",
            }
            
            response = await self._make_request(
                "GET",
                f"/repos/{owner}/{repo}/actions/runs",
                params=query_params
            )
            
            runs = response.get("workflow_runs", [])
            
            # Filter by time range
            filtered_runs = [
                r for r in runs
                if self._is_within_range(r.get("created_at", ""), start_time, end_time)
            ]
            
            return [self._transform_workflow_run(r) for r in filtered_runs]
        
        except Exception as e:
            logger.error(f"Failed to fetch workflow runs: {e}")
            return []
    
    async def _fetch_security_alerts(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Fetch security vulnerability alerts from GitHub."""
        try:
            # Dependabot alerts
            response = await self._make_request(
                "GET",
                f"/repos/{owner}/{repo}/dependabot/alerts",
                params={"per_page": 100, "state": "open"}
            )
            
            return [self._transform_security_alert(a) for a in response]
        
        except Exception as e:
            logger.error(f"Failed to fetch security alerts: {e}")
            return []
    
    def _transform_deployment(self, deployment: Dict[str, Any]) -> Dict[str, Any]:
        """Transform GitHub deployment to Bronze format."""
        # Get latest status
        statuses = deployment.get("statuses", [])
        latest_status = statuses[0] if statuses else {}
        
        return {
            "source": "github",
            "source_type": "deployment",
            "event_id": str(deployment.get("id")),
            "timestamp": deployment.get("created_at", datetime.utcnow().isoformat()),
            "severity": self._map_deployment_state_to_severity(latest_status.get("state", "")),
            "title": f"Deployment to {deployment.get('environment', 'unknown')}",
            "description": deployment.get("description", ""),
            "deployment_id": deployment.get("id"),
            "environment": deployment.get("environment", ""),
            "ref": deployment.get("ref", ""),
            "sha": deployment.get("sha", ""),
            "creator": deployment.get("creator", {}),
            "state": latest_status.get("state", ""),
            "statuses": statuses,
            "raw_data": deployment,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_release(self, release: Dict[str, Any]) -> Dict[str, Any]:
        """Transform GitHub release to Bronze format."""
        return {
            "source": "github",
            "source_type": "release",
            "event_id": str(release.get("id")),
            "timestamp": release.get("published_at", datetime.utcnow().isoformat()),
            "severity": "INFO",
            "title": f"Release: {release.get('name', release.get('tag_name', ''))}",
            "description": release.get("body", ""),
            "release_id": release.get("id"),
            "tag_name": release.get("tag_name", ""),
            "target_commitish": release.get("target_commitish", ""),
            "name": release.get("name", ""),
            "draft": release.get("draft", False),
            "prerelease": release.get("prerelease", False),
            "author": release.get("author", {}),
            "assets": release.get("assets", []),
            "html_url": release.get("html_url", ""),
            "raw_data": release,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_workflow_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        """Transform GitHub Actions workflow run to Bronze format."""
        return {
            "source": "github",
            "source_type": "workflow_run",
            "event_id": str(run.get("id")),
            "timestamp": run.get("created_at", datetime.utcnow().isoformat()),
            "severity": self._map_conclusion_to_severity(run.get("conclusion", "")),
            "title": f"Workflow: {run.get('name', '')}",
            "description": f"Run #{run.get('run_number', 0)} - {run.get('event', '')}",
            "workflow_id": run.get("workflow_id"),
            "run_number": run.get("run_number"),
            "event": run.get("event", ""),
            "status": run.get("status", ""),
            "conclusion": run.get("conclusion", ""),
            "head_branch": run.get("head_branch", ""),
            "head_sha": run.get("head_sha", ""),
            "actor": run.get("actor", {}),
            "triggering_actor": run.get("triggering_actor", {}),
            "html_url": run.get("html_url", ""),
            "raw_data": run,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_security_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Transform GitHub security alert to Bronze format."""
        vulnerability = alert.get("security_vulnerability", {})
        package = vulnerability.get("package", {})
        
        return {
            "source": "github",
            "source_type": "security_alert",
            "event_id": str(alert.get("number")),
            "timestamp": alert.get("created_at", datetime.utcnow().isoformat()),
            "severity": alert.get("security_advisory", {}).get("severity", "MEDIUM").upper(),
            "title": alert.get("security_advisory", {}).get("summary", ""),
            "description": alert.get("security_advisory", {}).get("description", ""),
            "alert_number": alert.get("number"),
            "state": alert.get("state", ""),
            "package_name": package.get("name", ""),
            "package_ecosystem": package.get("ecosystem", ""),
            "vulnerable_version_range": vulnerability.get("vulnerable_version_range", ""),
            "first_patched_version": vulnerability.get("first_patched_version", {}),
            "ghsa_id": alert.get("security_advisory", {}).get("ghsa_id", ""),
            "cve_id": alert.get("security_advisory", {}).get("cve_id", ""),
            "html_url": alert.get("html_url", ""),
            "raw_data": alert,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _is_within_range(timestamp_str: str, start_time: datetime, end_time: datetime) -> bool:
        """Check if timestamp is within the given range."""
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            # Make naive for comparison if needed
            if timestamp.tzinfo:
                timestamp = timestamp.replace(tzinfo=None)
            return start_time <= timestamp <= end_time
        except:
            return False
    
    @staticmethod
    def _map_deployment_state_to_severity(state: str) -> str:
        """Map deployment state to severity level."""
        mapping = {
            "error": "HIGH",
            "failure": "HIGH",
            "success": "INFO",
            "pending": "LOW",
            "in_progress": "LOW",
        }
        return mapping.get(state.lower(), "INFO")
    
    @staticmethod
    def _map_conclusion_to_severity(conclusion: str) -> str:
        """Map workflow conclusion to severity level."""
        mapping = {
            "failure": "HIGH",
            "cancelled": "MEDIUM",
            "success": "INFO",
            "skipped": "INFO",
        }
        return mapping.get(conclusion.lower(), "INFO")
