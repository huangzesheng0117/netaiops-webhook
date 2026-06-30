"""Evidence Hub package for NetAIOps Webhook v10."""

from .schema import (
    DEFAULT_BASE_DIR, DETAIL_ROOT_REL_PATH, REQUIRED_SECTION_FILES, SCHEMA_VERSION,
    ArtifactRef, DetailMeta, build_empty_detail, evidence_hub_root, request_detail_dir,
    safe_request_id, utc_now, validate_request_id,
)
from .writer import (SOURCE_PATTERNS, SourceArtifact, build_evidence_detail, find_request_artifacts)
from .list_api import (
    get_evidence_list,
    iter_evidence_request_summaries,
    list_api_route_manifest,
)
from .detail_api import (
    api_route_manifest,
    detail_exists,
    get_evidence_detail,
    get_evidence_device,
    get_evidence_metrics,
    get_evidence_review,
    get_evidence_section,
    get_evidence_summary,
)
from .detail_url import (
    build_detail_url, evidence_hub_default_to_local, evidence_hub_enabled,
    evidence_hub_url_config_summary, get_default_local_base_url, get_evidence_hub_base_url, normalize_base_url,
)
from .integration import (build_evidence_detail_safe,)
from .ui_api import (
    build_evidence_detail_html,
    build_evidence_index_html,
    ui_route_manifest,
)

__all__ = [
    "DEFAULT_BASE_DIR", "DETAIL_ROOT_REL_PATH", "REQUIRED_SECTION_FILES", "SCHEMA_VERSION",
    "ArtifactRef", "DetailMeta", "build_empty_detail", "evidence_hub_root", "request_detail_dir",
    "safe_request_id", "utc_now", "validate_request_id",
    "SOURCE_PATTERNS", "SourceArtifact", "build_evidence_detail", "find_request_artifacts",
    "build_detail_url", "evidence_hub_default_to_local", "evidence_hub_enabled",
    "evidence_hub_url_config_summary", "get_default_local_base_url", "get_evidence_hub_base_url", "normalize_base_url",
    "build_evidence_detail_safe",
    "get_evidence_summary",
    "get_evidence_section",
    "get_evidence_review",
    "get_evidence_metrics",
    "get_evidence_device",
    "get_evidence_detail",
    "detail_exists",
    "api_route_manifest",
    "list_api_route_manifest",
    "iter_evidence_request_summaries",
    "get_evidence_list",
    "build_evidence_index_html",
    "build_evidence_detail_html",
    "ui_route_manifest",
]
