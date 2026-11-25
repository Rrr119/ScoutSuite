import copy
import html
import json
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from ScoutSuite.core.compliance import ComplianceControl, ComplianceMapper


class CheckStatus(str, Enum):
    PASS = 'pass'
    FAIL = 'fail'
    UNKNOWN = 'unknown'
    NOT_APPLICABLE = 'not_applicable'


def _normalise_provider(provider):
    return str(provider or 'unknown').strip().lower()


def _normalise_rule_id(rule_id):
    rule_id = os.path.basename(str(rule_id or ''))
    return rule_id[:-5] if rule_id.lower().endswith('.json') else rule_id


def _rule_id_variants(rule_id):
    rule_id = os.path.basename(str(rule_id or ''))
    if not rule_id:
        return []
    normalised = _normalise_rule_id(rule_id)
    return list(OrderedDict.fromkeys([rule_id.lower(), normalised.lower()]))


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'enabled', 'on')
    return bool(value)


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    provider: str
    status: CheckStatus
    resource_id: Optional[str] = None
    rule_id: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            'check_id': self.check_id,
            'provider': self.provider,
            'status': self.status.value,
            'resource_id': self.resource_id,
            'rule_id': self.rule_id,
            'details': dict(self.details),
        }


@dataclass
class ProviderCheck:
    """
    Provider-specific implementation of a unified check.

    ``evaluator`` is a pure predicate. It receives a resource mapping and an
    optional context mapping, and returns ``True`` when the resource is
    compliant, ``False`` when it is not, or ``None`` when it cannot be decided.
    This makes rule decisions independent from ScoutSuite's recursive JSON
    traversal and straightforward to unit test.
    """

    provider: str
    evaluator: Optional[Callable[[Mapping[str, Any], Mapping[str, Any]], Any]] = None
    rule_ids: Tuple[str, ...] = ()
    resource_type: Optional[str] = None
    compliance: Tuple[ComplianceControl, ...] = ()

    def evaluate(self, resource, context=None):
        provider = _normalise_provider(self.provider)
        context = context or {}
        resource_id = context.get('resource_id')
        if resource_id is None and isinstance(resource, Mapping):
            resource_id = resource.get('id') or resource.get('name')

        if self.evaluator is None:
            return CheckResult(
                check_id=context.get('check_id', ''),
                provider=provider,
                status=CheckStatus.UNKNOWN,
                resource_id=resource_id,
                details={'reason': 'No evaluator registered for provider'},
            )

        try:
            outcome = self.evaluator(resource or {}, context)
        except Exception as exc:
            return CheckResult(
                check_id=context.get('check_id', ''),
                provider=provider,
                status=CheckStatus.UNKNOWN,
                resource_id=resource_id,
                details={'error': str(exc)},
            )

        if isinstance(outcome, CheckResult):
            return outcome

        details = {}
        if isinstance(outcome, Mapping):
            details = {key: value for key, value in outcome.items() if key not in ('status', 'passed', 'compliant')}
            if 'status' in outcome:
                try:
                    status = CheckStatus(outcome['status'])
                except ValueError:
                    status = CheckStatus.UNKNOWN
                    details['error'] = 'Unknown status: {}'.format(outcome['status'])
            else:
                passed = outcome.get('passed', outcome.get('compliant'))
                status = self._status_from_value(passed)
        else:
            status = self._status_from_value(outcome)

        return CheckResult(
            check_id=context.get('check_id', ''),
            provider=provider,
            status=status,
            resource_id=resource_id,
            details=details,
        )

    @staticmethod
    def _status_from_value(value):
        if value is None:
            return CheckStatus.UNKNOWN
        if isinstance(value, CheckStatus):
            return value
        if isinstance(value, str) and value in [status.value for status in CheckStatus]:
            return CheckStatus(value)
        return CheckStatus.PASS if bool(value) else CheckStatus.FAIL


@dataclass
class UnifiedCheck:
    id: str
    title: str
    description: str = ''
    severity: str = 'warning'
    remediation: str = ''
    references: Tuple[str, ...] = ()
    compliance: Tuple[ComplianceControl, ...] = ()
    providers: Dict[str, ProviderCheck] = field(default_factory=OrderedDict)

    def bind(self,
             provider,
             evaluator=None,
             rule_ids=None,
             resource_type=None,
             compliance=None):
        provider = _normalise_provider(provider)
        rule_ids = tuple(rule_ids or [])
        compliance = tuple(compliance or [])
        if provider in self.providers:
            binding = self.providers[provider]
            binding.rule_ids = tuple(OrderedDict.fromkeys(binding.rule_ids + rule_ids))
            if evaluator is not None:
                binding.evaluator = evaluator
            if resource_type is not None:
                binding.resource_type = resource_type
            if compliance:
                controls = {(item.framework, item.version, item.control, item.provider or ''): item
                            for item in binding.compliance + compliance}
                binding.compliance = tuple(controls.values())
        else:
            self.providers[provider] = ProviderCheck(
                provider=provider,
                evaluator=evaluator,
                rule_ids=rule_ids,
                resource_type=resource_type,
                compliance=compliance,
            )
        return self

    def evaluate(self, provider, resource, context=None):
        provider = _normalise_provider(provider)
        context = dict(context or {})
        context.setdefault('check_id', self.id)
        binding = self.providers.get(provider)
        if binding is None:
            return CheckResult(
                check_id=self.id,
                provider=provider,
                status=CheckStatus.NOT_APPLICABLE,
                details={'reason': 'Check is not implemented for this provider'},
            )
        return binding.evaluate(resource, context)

    def evaluate_many(self, provider, resources, resource_id_key='id'):
        if isinstance(resources, Mapping):
            for key, resource in resources.items():
                yield self.evaluate(provider, resource, {'resource_id': str(key)})
            return
        for index, resource in enumerate(resources or []):
            resource_id = None
            if isinstance(resource, Mapping):
                resource_id = resource.get(resource_id_key)
            yield self.evaluate(provider, resource, {'resource_id': str(resource_id or index)})

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'remediation': self.remediation,
            'references': list(self.references),
            'compliance': [control.to_dict() for control in self.compliance],
            'providers': {
                provider: {
                    'rule_ids': list(binding.rule_ids),
                    'resource_type': binding.resource_type,
                    'compliance': [control.to_dict() for control in binding.compliance],
                }
                for provider, binding in self.providers.items()
            },
        }


class UnifiedCheckRegistry:
    def __init__(self, checks=None):
        self.checks = OrderedDict()
        self._rule_index = {}
        for check in checks or []:
            self.register(check)

    def register(self, check, overwrite=False):
        if check.id in self.checks and not overwrite:
            raise ValueError('Unified check "{}" is already registered'.format(check.id))
        self.checks[check.id] = check
        for provider, binding in check.providers.items():
            for rule_id in binding.rule_ids:
                for variant in _rule_id_variants(rule_id):
                    self._rule_index.setdefault((_normalise_provider(provider), variant), set()).add(check.id)
        return check

    def create(self, check_id, title=None, **kwargs):
        return self.register(UnifiedCheck(
            id=check_id,
            title=title or check_id.replace('.', ' ').replace('_', ' ').title(),
            **kwargs
        ))

    def get(self, check_id, default=None):
        return self.checks.get(check_id, default)

    def __getitem__(self, check_id):
        return self.checks[check_id]

    def checks_for_rule(self, provider, rule_id):
        provider = _normalise_provider(provider)
        check_ids = []
        for variant in _rule_id_variants(rule_id):
            check_ids.extend(self._rule_index.get((provider, variant), []))
        return [self.checks[check_id] for check_id in OrderedDict.fromkeys(check_ids)]

    def to_dict(self):
        return {'checks': [check.to_dict() for check in self.checks.values()]}

    def copy(self):
        return UnifiedCheckRegistry(
            [copy.deepcopy(check) for check in self.checks.values()]
        )


def aws_object_storage_is_public(resource, context=None):
    resource = resource or {}
    if 'public_access' in resource:
        return not _as_bool(resource['public_access'])

    grantees = resource.get('grantees') or resource.get('acl') or []
    if isinstance(grantees, Mapping):
        grantees = list(grantees.values())
    for grantee in grantees or []:
        if not isinstance(grantee, Mapping):
            continue
        uri = str(grantee.get('URI') or grantee.get('uri') or '')
        permissions = grantee.get('permissions') or {}
        is_public_grantee = uri.rstrip('/').endswith(('AllUsers', 'AuthenticatedUsers'))
        if is_public_grantee and (not permissions or any(_as_bool(value) for value in permissions.values())):
            return False

    policy = resource.get('policy') or {}
    statements = policy.get('Statement', []) if isinstance(policy, Mapping) else []
    if isinstance(statements, Mapping):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get('Effect') != 'Allow':
            continue
        principal = statement.get('Principal')
        if principal == '*' or principal == {'AWS': '*'}:
            actions = statement.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            if any(str(action).lower() in ('*', 's3:*') for action in actions):
                return False

    if 'grantees' in resource or 'acl' in resource or 'policy' in resource:
        return True
    return None


def azure_storage_is_public(resource, context=None):
    resource = resource or {}
    for key in ('public_access_allowed', 'allow_blob_public_access'):
        if key in resource:
            return not _as_bool(resource[key])
    return None


def gcp_storage_is_public(resource, context=None):
    resource = resource or {}
    prevention = str(resource.get('public_access_prevention') or '').lower()
    if prevention in ('enforced', 'inherited'):
        return True

    members = []
    member_bindings = resource.get('member_bindings') or {}
    if isinstance(member_bindings, Mapping):
        members.extend(member_bindings.keys())
        for value in member_bindings.values():
            if isinstance(value, Mapping):
                members.extend(value.keys())
    elif isinstance(member_bindings, list):
        members.extend(member_bindings)
    members.extend(resource.get('members') or [])
    members.extend(resource.get('acls') or [])

    public_members = {'allusers', 'allauthenticatedusers'}
    found_binding = bool(members)
    for member in members:
        member_text = str(member).lower()
        if member_text.split(':')[-1] in public_members or any(
                public_member in member_text for public_member in public_members):
            return False
    return True if found_binding else None


def default_registry():
    return _DEFAULT_REGISTRY.copy()


def _build_default_registry():
    registry = UnifiedCheckRegistry()
    registry.create(
        'storage.public_access',
        title='Object storage is not publicly accessible',
        description=(
            'Object storage buckets, containers, accounts, or their ACL/IAM policies '
            'must not grant public access.'
        ),
        severity='danger',
        remediation='Remove public ACLs and IAM policy grants from the storage resource.',
    ).bind(
        'aws',
        evaluator=aws_object_storage_is_public,
        rule_ids=['s3-bucket-world-policy-star.json'],
        resource_type='object_storage',
        compliance=[
            ComplianceControl('cis', '1.2.0', '2.3', 'CIS Foundations', 'aws'),
        ],
    ).bind(
        'azure',
        evaluator=azure_storage_is_public,
        rule_ids=['storageaccount-public-blob-container.json'],
        resource_type='object_storage',
        compliance=[
            ComplianceControl('cis', '1.2.0', '3.5', 'CIS Foundations', 'azure'),
        ],
    ).bind(
        'gcp',
        evaluator=gcp_storage_is_public,
        rule_ids=['cloudstorage-bucket-member.json'],
        resource_type='object_storage',
        compliance=[
            ComplianceControl('cis', '1.0.0', '5.1', 'CIS Foundations', 'gcp'),
            ComplianceControl('cis', '1.1.0', '5.1', 'CIS Foundations', 'gcp'),
        ],
    )
    return registry


_DEFAULT_REGISTRY = _build_default_registry()


def _finding_items(finding):
    items = []
    for item in finding.get('items') or []:
        if isinstance(item, (dict, list)):
            items.append(json.dumps(item, sort_keys=True, separators=(',', ':')))
        else:
            items.append(str(item))
    return items


def _finding_rule_id(finding, finding_key):
    return finding.get('rule_id') or finding.get('filename') or finding_key


def _check_ids_for_finding(registry, provider, finding, finding_key):
    check_ids = []
    metadata = finding.get('unified_check') or finding.get('unified_check_id')
    if isinstance(metadata, str):
        check_ids.append(metadata)
    elif isinstance(metadata, Mapping):
        check_id = metadata.get('id') or metadata.get('check_id')
        if check_id:
            check_ids.append(check_id)

    rule_id = _finding_rule_id(finding, finding_key)
    for check in registry.checks_for_rule(provider, rule_id):
        check_ids.append(check.id)
    for check in registry.checks_for_rule(provider, finding_key):
        check_ids.append(check.id)
    return list(OrderedDict.fromkeys(check_ids))


class CrossCloudCheckAggregator:
    """
    Aggregates existing ScoutSuite findings into one table row per unified check.

    The aggregator only reads the existing ``services.<service>.findings``
    structure. It does not modify or replace that structure, so reports remain
    compatible with older ScoutSuite consumers.
    """

    def __init__(self, registry=None, mapper=None, reports=None):
        if registry is not None and not isinstance(registry, UnifiedCheckRegistry):
            if reports is not None:
                raise TypeError('reports must not be supplied twice')
            reports = registry
            registry = None
        self.registry = registry.copy() if registry is not None else default_registry()
        self.mapper = mapper or ComplianceMapper()
        self.providers = []
        self.provider_names = {}
        self._findings = OrderedDict()
        if reports is not None:
            self.add_reports(reports)

    def _remember_provider(self, provider, provider_name=None):
        provider = _normalise_provider(provider)
        if provider not in self.providers:
            self.providers.append(provider)
        if provider_name:
            self.provider_names[provider] = provider_name
        return provider

    def add_report(self, report, provider=None):
        if not isinstance(report, Mapping):
            if not hasattr(report, 'services'):
                raise TypeError('Report must be a mapping or expose a services attribute')
            report = {
                'provider_code': getattr(report, 'provider_code', provider),
                'provider_name': getattr(report, 'provider_name', None),
                'services': report.services,
            }
        provider = provider or report.get('provider_code') or report.get('provider')
        provider = self._remember_provider(provider, report.get('provider_name'))

        services = report.get('services', report)
        if not isinstance(services, Mapping):
            return self

        for service_name, service in services.items():
            if not isinstance(service, Mapping):
                continue
            findings = service.get('findings') or {}
            if not isinstance(findings, Mapping):
                continue
            for finding_key, finding in findings.items():
                if not isinstance(finding, Mapping):
                    continue
                check_ids = _check_ids_for_finding(self.registry, provider, finding, finding_key)
                for check_id in check_ids:
                    if self.registry.get(check_id) is None:
                        metadata = finding.get('unified_check')
                        metadata = metadata if isinstance(metadata, Mapping) else {}
                        self.registry.create(
                            check_id,
                            title=metadata.get('title'),
                            description=metadata.get('description', ''),
                            severity=metadata.get('severity', 'warning'),
                            remediation=metadata.get('remediation', ''),
                        )
                    provider_findings = self._findings.setdefault(check_id, OrderedDict())
                    provider_findings.setdefault(provider, []).append(finding)
        return self

    def add_reports(self, reports):
        if isinstance(reports, Mapping):
            reports = [reports]
        elif not isinstance(reports, (list, tuple, set)):
            reports = [reports]
        elif (isinstance(reports, tuple) and len(reports) == 2
              and isinstance(reports[0], str) and isinstance(reports[1], Mapping)):
            reports = [reports]
        for report in reports:
            if isinstance(report, (tuple, list)) and len(report) == 2:
                provider, report_data = report
                self.add_report(report_data, provider=provider)
            else:
                self.add_report(report)
        return self

    @classmethod
    def from_reports(cls, reports, registry=None, mapper=None):
        aggregator = cls(registry=registry, mapper=mapper)
        aggregator.add_reports(reports)
        return aggregator

    def _provider_summary(self, check, provider):
        findings = self._findings.get(check.id, {}).get(provider, [])
        checked = 0
        flagged = 0
        items = []
        rule_ids = []
        compliance = []
        resource_type = None
        for finding in findings:
            try:
                finding_checked = int(finding.get('checked_items') or 0)
            except (TypeError, ValueError):
                finding_checked = 0
            try:
                finding_flagged = int(finding.get('flagged_items') or 0)
            except (TypeError, ValueError):
                finding_flagged = 0
            checked = max(checked, finding_checked)
            flagged = max(flagged, finding_flagged)
            items.extend(_finding_items(finding))
            rule_ids.append(_finding_rule_id(finding, ''))
            resource_type = resource_type or finding.get('resource_type')
            compliance.extend(self.mapper.map_many(finding.get('compliance') or [], provider))
            metadata = finding.get('unified_check')
            if isinstance(metadata, Mapping):
                compliance.extend(self.mapper.map_many(metadata.get('compliance') or [], provider))
                resource_type = resource_type or metadata.get('resource_type')

        unique_items = list(OrderedDict.fromkeys(items))
        failed = len(unique_items) if unique_items else flagged
        checked = max(checked, failed)
        passed = max(checked - failed, 0)
        if failed:
            status = CheckStatus.FAIL
        elif checked:
            status = CheckStatus.PASS
        else:
            status = CheckStatus.UNKNOWN

        binding = check.providers.get(provider)
        if binding:
            rule_ids.extend(binding.rule_ids)
            resource_type = resource_type or binding.resource_type
            compliance.extend(binding.compliance)
        compliance.extend(check.compliance)
        controls = []
        seen = set()
        for control in self.mapper.sort(compliance):
            if control.key not in seen:
                seen.add(control.key)
                controls.append(control)

        return {
            'provider': provider,
            'status': status.value,
            'checked': checked,
            'passed': passed,
            'failed': failed,
            'checked_items': checked,
            'passed_items': passed,
            'flagged_items': failed,
            'rule_ids': sorted(set(filter(None, rule_ids))),
            'resource_type': resource_type,
            'compliance': [control.to_dict() for control in controls],
        }

    @staticmethod
    def _summary_status(provider_results):
        statuses = [result['status'] for result in provider_results.values()]
        if CheckStatus.FAIL.value in statuses:
            return CheckStatus.FAIL.value
        if statuses and all(status == CheckStatus.PASS.value for status in statuses):
            return CheckStatus.PASS.value
        return CheckStatus.UNKNOWN.value

    def _build_row(self, check):
        provider_results = OrderedDict()
        for provider in self.providers:
            provider_results[provider] = self._provider_summary(check, provider)

        all_controls = []
        for result in provider_results.values():
            all_controls.extend(self.mapper.map_many(result['compliance'], result['provider']))
        unique_controls = []
        seen = set()
        for control in self.mapper.sort(all_controls):
            if control.key not in seen:
                seen.add(control.key)
                unique_controls.append(control)

        summary = {
            'status': self._summary_status(provider_results),
            'checked': sum(result['checked'] for result in provider_results.values()),
            'passed': sum(result['passed'] for result in provider_results.values()),
            'failed': sum(result['failed'] for result in provider_results.values()),
        }
        summary['checked_items'] = summary['checked']
        summary['passed_items'] = summary['passed']
        summary['flagged_items'] = summary['failed']

        return {
            'id': check.id,
            'title': check.title,
            'description': check.description,
            'severity': check.severity,
            'level': check.severity,
            'remediation': check.remediation,
            'references': list(check.references),
            'providers': provider_results,
            'summary': summary,
            'compliance': [control.to_dict() for control in unique_controls],
            'frameworks': self.mapper.group_by_framework(unique_controls),
        }

    def as_table(self, framework=None, version=None):
        rows = [self._build_row(check) for check in self.registry.checks.values()]
        if framework is None:
            return rows
        framework = self.mapper.normalise_framework(framework)[0]
        filtered = []
        for row in rows:
            controls = [
                control for control in row['compliance']
                if control['framework'] == framework
                and (version is None or control['version'] == str(version))
            ]
            if controls:
                filtered_row = dict(row)
                filtered_row['compliance'] = controls
                filtered_row['frameworks'] = self.mapper.group_by_framework(
                    self.mapper.map_many(controls)
                )
                filtered.append(filtered_row)
        return filtered

    def to_dict(self, framework=None, version=None):
        rows = self.as_table(framework=framework, version=version)
        all_controls = []
        for row in rows:
            all_controls.extend(self.mapper.map_many(row['compliance']))
        return {
            'checks': rows,
            'providers': [
                {
                    'id': provider,
                    'name': self.provider_names.get(provider, provider.upper()),
                }
                for provider in self.providers
            ],
            'frameworks': self.mapper.group_by_framework(all_controls),
        }

    def to_html(self, framework=None, version=None):
        """
        Render the aggregated rows as a standalone table. This is intentionally
        plain HTML so it can be embedded in ScoutSuite's report or used by
        downstream tooling.
        """
        rows = self.as_table(framework=framework, version=version)
        headers = ''.join(
            '<th>{}</th>'.format(html.escape(self.provider_names.get(provider, provider.upper())))
            for provider in self.providers
        )
        body = []
        for row in rows:
            cells = []
            for provider in self.providers:
                result = row['providers'][provider]
                cells.append(
                    '<td class="unified-check-{}">{}<br><small>{} / {} passed / {} failed</small></td>'.format(
                        html.escape(result['status']),
                        html.escape(result['status'].upper()),
                        result['checked'],
                        result['passed'],
                        result['failed'],
                    )
                )
            body.append(
                '<tr><td><strong>{}</strong><br><small>{}</small></td>{}</tr>'.format(
                    html.escape(row['title']),
                    html.escape(row['id']),
                    ''.join(cells),
                )
            )
        return (
            '<table class="table table-striped unified-checks-table">'
            '<thead><tr><th>Unified check</th>{}</tr></thead><tbody>{}</tbody></table>'
        ).format(headers, ''.join(body))


def aggregate_cross_cloud_checks(reports, registry=None, mapper=None, framework=None, version=None):
    """
    Build a cross-cloud table from one or more ScoutSuite report dictionaries.

    Reports can be supplied as full result documents, or as
    ``(provider, report)`` pairs when the provider code is not present in the
    document.
    """
    if isinstance(reports, Mapping):
        reports = [reports]
    elif not isinstance(reports, (list, tuple, set)):
        reports = [reports]
    aggregator = CrossCloudCheckAggregator.from_reports(reports, registry=registry, mapper=mapper)
    return aggregator.to_dict(framework=framework, version=version)


def attach_unified_checks(provider, report, registry=None, mapper=None):
    """
    Add a ``unified_checks`` section to an existing report without changing its
    legacy ``services`` data. Returns the generated section.
    """
    aggregator = CrossCloudCheckAggregator(registry=registry, mapper=mapper)
    aggregator.add_report(report, provider=provider)
    result = aggregator.to_dict()
    report['unified_checks'] = result
    return result


def load_report_file(path):
    """
    Load either a JSON report or ScoutSuite's JavaScript results file.
    """
    with open(path, 'r') as report_file:
        content = report_file.read().strip()
    if content.startswith('scoutsuite_results'):
        content = content.split('=', 1)[1].strip()
    if content.endswith(';'):
        content = content[:-1].rstrip()
    return json.loads(content)


def aggregate_report_files(paths, registry=None, mapper=None, framework=None, version=None):
    """
    Aggregate existing ScoutSuite result files without a network run.
    """
    if isinstance(paths, str):
        paths = [paths]
    reports = [load_report_file(path) for path in paths]
    return aggregate_cross_cloud_checks(
        reports,
        registry=registry,
        mapper=mapper,
        framework=framework,
        version=version,
    )


def render_cross_cloud_table(reports, registry=None, mapper=None, framework=None, version=None):
    """
    Build a standalone HTML table for one or more report dictionaries.
    """
    aggregator = CrossCloudCheckAggregator.from_reports(reports, registry=registry, mapper=mapper)
    return aggregator.to_html(framework=framework, version=version)


# Short aliases for integrations that refer to the abstraction as a "check".
Check = UnifiedCheck
CheckRegistry = UnifiedCheckRegistry
CrossCloudAggregator = CrossCloudCheckAggregator
aggregate_checks = aggregate_cross_cloud_checks
