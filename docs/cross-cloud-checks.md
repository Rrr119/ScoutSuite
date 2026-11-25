# Cross-cloud checks

ScoutSuite has a provider-neutral check layer for comparing the same security
control across AWS, Azure, and GCP while keeping the existing per-provider rule
and report formats unchanged.

## Concepts

- `UnifiedCheck` defines one check ID, its title/severity/remediation, provider
  bindings, and compliance controls.
- `ProviderCheck` binds a provider to one or more existing ScoutSuite rule IDs
  and an optional pure predicate.
- `ComplianceMapper` normalizes provider-specific CIS names such as
  `CIS Amazon Web Services Foundations` into the canonical `cis` framework.
- `CrossCloudCheckAggregator` reads existing
  `services.<service>.findings` data and produces one table row per unified
  check.

## Extending a check

```python
from ScoutSuite.core.unified_checks import UnifiedCheckRegistry

registry = UnifiedCheckRegistry()
registry.create(
    'storage.public_access',
    title='Object storage is not publicly accessible',
    severity='danger',
).bind(
    'aws',
    rule_ids=['s3-bucket-world-policy-star.json'],
    evaluator=lambda resource, context: not resource.get('public_access', False),
)
```

The evaluator receives a resource dictionary and returns `True` for compliant,
`False` for non-compliant, or `None` when the decision is unknown. It has no
dependency on ScoutSuite's recursive JSON traversal, so it can be tested with a
plain unit test.

Existing rule definitions can opt into a unified check without changing their
conditions:

```json
{
    "unified_check": {
        "id": "storage.public_access",
        "title": "Object storage is not publicly accessible"
    }
}
```

## Aggregating existing reports

```python
from ScoutSuite.core.unified_checks import aggregate_report_files

table = aggregate_report_files([
    'scoutsuite-report/scoutsuite-results/scoutsuite_results_aws.js',
    'scoutsuite-report/scoutsuite-results/scoutsuite_results_azure.js',
    'scoutsuite-report/scoutsuite-results/scoutsuite_results_gcp.js',
], framework='cis', version='1.2.0')

for row in table['checks']:
    print(row['id'], {
        provider: result['status']
        for provider, result in row['providers'].items()
    })
```

Each row has a `providers` mapping with `status`, `checked`, `passed`, `failed`,
and `compliance` values, plus a cross-provider `summary`.
`render_cross_cloud_table()` renders the same rows as a standalone HTML table.

## Report compatibility

The legacy `services.*.findings` structure remains authoritative and unchanged.
ScoutSuite only adds:

- `rule_id` and optional `unified_check` metadata to finding entries.
- A top-level `unified_checks` section to generated reports.

Consumers that do not understand the new fields can continue reading the report
as before.
