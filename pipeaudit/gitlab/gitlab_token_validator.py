"""Validate GitLab PAT by probing the groups API."""

from __future__ import annotations

import logging
import urllib.parse

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://gitlab.com/api/v4"


class GitLabTokenError(Exception):
    """Raised when the GitLab PAT is invalid or lacks permissions."""


def validate_gitlab_token(
    group: str, token: str, base_url: str = DEFAULT_BASE_URL
) -> dict:
    """Validate the PAT by calling the groups endpoint.

    Returns basic group info dict on success.
    Raises GitLabTokenError on failure.
    """
    encoded = urllib.parse.quote(group, safe="")
    url = f"{base_url.rstrip('/')}/groups/{encoded}"
    headers = {"PRIVATE-TOKEN": token}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        raise GitLabTokenError(f"Failed to connect to GitLab: {e}") from e

    if resp.status_code == 401:
        raise GitLabTokenError(
            "GitLab PAT authentication failed. "
            "Ensure the token is valid and not expired."
        )
    if resp.status_code == 403:
        raise GitLabTokenError(
            "GitLab PAT lacks permission to access the group. "
            "Ensure the PAT has 'read_api' scope."
        )
    if resp.status_code == 404:
        raise GitLabTokenError(
            f"GitLab group '{group}' not found. "
            "Check the group path."
        )
    resp.raise_for_status()

    data = resp.json()
    return {
        "group": data.get("full_path", group),
        "group_name": data.get("name", ""),
        "visibility": data.get("visibility", ""),
    }
