import re
from dataclasses import dataclass
from typing import Mapping, Optional


DEFAULT_FRAMEWORK_ALIASES = {
    'cis amazon web services foundations': ('cis', 'CIS Foundations'),
    'cis microsoft azure foundations': ('cis', 'CIS Foundations'),
    'cis google cloud platform foundations': ('cis', 'CIS Foundations'),
    'cis gke benchmark': ('cis-gke', 'CIS GKE Benchmark'),
}

DEFAULT_FRAMEWORK_NAMES = {
    'cis': 'CIS Foundations',
    'cis-gke': 'CIS GKE Benchmark',
}


def _normalise_name(value):
    return re.sub(r'\s+', ' ', str(value or '')).strip()


def _framework_id(value):
    value = _normalise_name(value).lower()
    value = re.sub(r'[^a-z0-9]+', '-', value).strip('-')
    return value or 'unknown'


@dataclass(frozen=True)
class ComplianceControl:
    """
    A provider-neutral representation of a compliance control.

    ``framework`` is a stable identifier (for example, ``cis``), while
    ``framework_name`` is the human-readable framework name used in reports.
    """

    framework: str
    version: str
    control: str
    framework_name: Optional[str] = None
    provider: Optional[str] = None

    @property
    def key(self):
        return self.framework, self.version, self.control, self.provider or ''

    def to_dict(self):
        return {
            'name': self.framework_name or self.framework,
            'framework': self.framework,
            'framework_name': self.framework_name or self.framework,
            'version': self.version,
            'control': self.control,
            'reference': self.control,
            'id': '{}:{}:{}'.format(self.framework, self.version, self.control),
            'provider': self.provider,
        }


class ComplianceMapper:
    """
    Maps existing provider-specific compliance entries to canonical frameworks.

    The original ScoutSuite rule format uses entries such as::

        {
            "name": "CIS Amazon Web Services Foundations",
            "version": "1.2.0",
            "reference": "2.3"
        }

    This class keeps that format intact while also exposing a canonical
    ``framework`` identifier and control reference that can be compared across
    cloud providers.
    """

    def __init__(self, aliases=None):
        self.aliases = dict(DEFAULT_FRAMEWORK_ALIASES)
        if aliases:
            self.aliases.update({_normalise_name(key).lower(): value for key, value in aliases.items()})

    def add_alias(self, name, framework, framework_name=None):
        self.aliases[_normalise_name(name).lower()] = (
            _framework_id(framework),
            framework_name or name,
        )

    def normalise_framework(self, name):
        name = _normalise_name(name)
        alias = self.aliases.get(name.lower())
        if alias:
            return alias
        framework = _framework_id(name)
        return framework, DEFAULT_FRAMEWORK_NAMES.get(framework, name or 'Unknown')

    def map(self, entry, provider=None):
        if isinstance(entry, ComplianceControl):
            if provider and not entry.provider:
                return ComplianceControl(
                    framework=entry.framework,
                    version=entry.version,
                    control=entry.control,
                    framework_name=entry.framework_name,
                    provider=provider,
                )
            return entry

        if isinstance(entry, str):
            parts = entry.split(':', 2)
            if len(parts) != 3:
                raise ValueError('Compliance strings must use framework:version:control')
            framework, version, control = parts
            framework_id, framework_name = self.normalise_framework(framework)
            return ComplianceControl(
                framework=framework_id,
                version=version,
                control=control,
                framework_name=framework_name,
                provider=provider,
            )

        if not isinstance(entry, Mapping):
            raise TypeError('Compliance entries must be mappings or strings')

        framework_name = entry.get('name') or entry.get('framework_name') or entry.get('framework') or 'Unknown'
        if entry.get('framework'):
            framework = _framework_id(entry['framework'])
            framework_display_name = (
                entry.get('framework_name')
                or DEFAULT_FRAMEWORK_NAMES.get(framework)
                or entry['framework']
            )
        else:
            framework, framework_display_name = self.normalise_framework(framework_name)

        return ComplianceControl(
            framework=framework,
            version=str(entry.get('version') or ''),
            control=str(entry.get('control') or entry.get('reference') or ''),
            framework_name=framework_display_name,
            provider=provider or entry.get('provider'),
        )

    def map_many(self, entries, provider=None):
        controls = []
        seen = set()
        for entry in entries or []:
            control = self.map(entry, provider)
            if control.key not in seen:
                seen.add(control.key)
                controls.append(control)
        return controls

    def sort(self, controls):
        return sorted(
            controls,
            key=lambda item: (
                item.framework,
                item.version,
                item.control,
                item.provider or '',
            ),
        )

    @staticmethod
    def group_by_framework(controls):
        groups = {}
        seen = set()
        for control in controls:
            if control.key in seen:
                continue
            seen.add(control.key)
            group = groups.setdefault(control.framework, {
                'id': control.framework,
                'name': control.framework_name or control.framework,
                'controls': [],
            })
            group['controls'].append(control.to_dict())
        for group in groups.values():
            group['controls'].sort(
                key=lambda item: (item['version'], item['control'], item.get('provider') or '')
            )
        return sorted(groups.values(), key=lambda item: item['id'])


def map_compliance(entries, provider=None, mapper=None):
    mapper = mapper or ComplianceMapper()
    return [control.to_dict() for control in mapper.map_many(entries, provider)]
