"""Validate Azure DevOps PAT by probing the projects API."""

from __future__ import annotations

import base64
import logging

import requests

logger = logging.getLogger(__name__)

ADO_BASE = "https://dev.azure.com"


class AdoTokenError(Exception):
    """Raised when the ADO PAT is invalid or lacks permissions."""


def validate_ado_token(org: str, token: str) -> dict:
    """Validate the PAT by calling the projects endpoint.

    Returns basic org info dict on success.
    Raises AdoTokenError on failure.
    """
    b64 = base64.b64encode(f":{token}".encode()).decode()
    headers = {
        "Authorization": f"Basic {b64}",
        "Content-Type": "application/json",
    }
    url = f"{ADO_BASE}/{org}/_apis/projects"
    resp = requests.get(
        url,
        headers=headers,
        params={"api-version": "7.1", "$top": "1"},
        timeout=30,
    )

    if resp.status_code == 401:
        raise AdoTokenError(
            "Azure DevOps PAT authentication failed. "
            "Ensure the token is valid and not expired."
        )
    if resp.status_code == 403:
        raise AdoTokenError(
            "Azure DevOps PAT lacks permission to list projects. "
            "Ensure the PAT has 'Project and Team: Read' scope."
        )
    if resp.status_code == 404:
        raise AdoTokenError(
            f"Azure DevOps organization '{org}' not found. "
            "Check the organization name."
        )
    resp.raise_for_status()

    data = resp.json()
    project_count = data.get("count", len(data.get("value", [])))
    return {"organization": org, "project_count": project_count}
