"""
Compatibility import for the cross-cloud check abstraction.

The implementation lives in :mod:`ScoutSuite.core.unified_checks`.
"""

from ScoutSuite.core.unified_checks import (  # noqa: F401
    Check,
    CheckRegistry,
    CheckResult,
    CheckStatus,
    CrossCloudAggregator,
    CrossCloudCheckAggregator,
    ProviderCheck,
    UnifiedCheck,
    UnifiedCheckRegistry,
    aggregate_checks,
    aggregate_cross_cloud_checks,
    aggregate_report_files,
    attach_unified_checks,
    default_registry,
    load_report_file,
    render_cross_cloud_table,
)
