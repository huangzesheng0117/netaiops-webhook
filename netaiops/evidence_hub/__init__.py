"""Evidence Hub package for NetAIOps Webhook v10.

Batch 1 only provides schema primitives. It does not integrate with the
production alert pipeline yet.
"""

from .schema import (
    DEFAULT_BASE_DIR,
    DETAIL_ROOT_REL_PATH,
    REQUIRED_SECTION_FILES,
    SCHEMA_VERSION,
    ArtifactRef,
    DetailMeta,
    build_empty_detail,
    evidence_hub_root,
    request_detail_dir,
    safe_request_id,
    utc_now,
    validate_request_id,
)

__all__ = [
    "DEFAULT_BASE_DIR",
    "DETAIL_ROOT_REL_PATH",
    "REQUIRED_SECTION_FILES",
    "SCHEMA_VERSION",
    "ArtifactRef",
    "DetailMeta",
    "build_empty_detail",
    "evidence_hub_root",
    "request_detail_dir",
    "safe_request_id",
    "utc_now",
    "validate_request_id",
]
