import copy
import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from ScoutSuite.core.compliance import ComplianceMapper
from ScoutSuite.core.unified_checks import (
    CheckStatus,
    CrossCloudCheckAggregator,
    UnifiedCheck,
    UnifiedCheckRegistry,
    aggregate_cross_cloud_checks,
    aggregate_report_files,
    attach_unified_checks,
    default_registry,
    load_report_file,
)


def _finding(checked, flagged, items=None, compliance=None, rule_id=None):
    finding = {
        'checked_items': checked,
        'flagged_items': flagged,
        'items': items or [],
    }
    if compliance:
        finding['compliance'] = compliance
    if rule_id:
        finding['rule_id'] = rule_id
    return finding


class TestUnifiedChecks(unittest.TestCase):

    def test_three_cloud_rules_declare_the_same_check(self):
        rule_paths = [
            'ScoutSuite/providers/aws/rules/findings/s3-bucket-world-policy-star.json',
            'ScoutSuite/providers/azure/rules/findings/storageaccount-public-blob-container.json',
            'ScoutSuite/providers/gcp/rules/findings/cloudstorage-bucket-member.json',
        ]
        for rule_path in rule_paths:
            with open(rule_path) as rule_file:
                rule = json.load(rule_file)
            self.assertEqual(rule['unified_check']['id'], 'storage.public_access')

    def test_rule_decisions_are_unit_testable(self):
        check = default_registry().get('storage.public_access')

        self.assertEqual(check.evaluate('aws', {'public_access': True}).status, CheckStatus.FAIL)
        self.assertEqual(check.evaluate('aws', {'public_access': False}).status, CheckStatus.PASS)
        self.assertEqual(check.evaluate('azure', {'public_access_allowed': True}).status, CheckStatus.FAIL)
        self.assertEqual(check.evaluate('azure', {'allow_blob_public_access': False}).status, CheckStatus.PASS)
        self.assertEqual(
            check.evaluate(
                'gcp',
                {'member_bindings': {'allUsers': {'roles/storage.objectViewer': True}}},
            ).status,
            CheckStatus.FAIL,
        )
        self.assertEqual(
            check.evaluate(
                'gcp',
                {'member_bindings': {'user:analyst@example.com': {'roles/storage.objectViewer': True}}},
            ).status,
            CheckStatus.PASS,
        )
        self.assertEqual(check.evaluate('gcp', {}).status, CheckStatus.UNKNOWN)

    def test_custom_check_can_be_defined_without_json_traversal(self):
        registry = UnifiedCheckRegistry()
        registry.create(
            'custom.encryption_enabled',
            title='Encryption enabled',
        ).bind(
            'aws',
            evaluator=lambda resource, context: resource.get('encrypted') is True,
        )

        check = registry.get('custom.encryption_enabled')
        self.assertEqual(check.evaluate('aws', {'encrypted': True}).status, CheckStatus.PASS)
        self.assertEqual(check.evaluate('aws', {'encrypted': False}).status, CheckStatus.FAIL)

    def test_compliance_frameworks_are_mapped_across_providers(self):
        mapper = ComplianceMapper()
        aws = mapper.map({
            'name': 'CIS Amazon Web Services Foundations',
            'version': '1.2.0',
            'reference': '2.3',
        }, provider='aws')
        azure = mapper.map({
            'name': 'CIS Microsoft Azure Foundations',
            'version': '1.2.0',
            'reference': '3.5',
        }, provider='azure')
        gcp = mapper.map({
            'name': 'CIS Google Cloud Platform Foundations',
            'version': '1.0.0',
            'reference': '5.1',
        }, provider='gcp')

        self.assertEqual(aws.framework, 'cis')
        self.assertEqual(azure.framework, 'cis')
        self.assertEqual(gcp.framework, 'cis')
        self.assertEqual(aws.framework_name, 'CIS Foundations')
        self.assertEqual(aws.to_dict()['id'], 'cis:1.2.0:2.3')

        grouped = mapper.group_by_framework([aws, azure, gcp])
        self.assertEqual(len(grouped), 1)
        self.assertEqual(len(grouped[0]['controls']), 3)

    def test_three_clouds_aggregate_to_one_row(self):
        reports = [
            {
                'provider_code': 'aws',
                'services': {
                    's3': {
                        'findings': {
                            's3-bucket-world-policy-star': _finding(
                                4,
                                1,
                                ['s3.buckets.public'],
                                [{'name': 'CIS Amazon Web Services Foundations',
                                  'version': '1.2.0', 'reference': '2.3'}],
                                's3-bucket-world-policy-star.json',
                            ),
                        },
                    },
                },
            },
            {
                'provider_code': 'azure',
                'services': {
                    'storageaccounts': {
                        'findings': {
                            'storageaccount-public-blob-container': _finding(
                                3,
                                0,
                                [],
                                [{'name': 'CIS Microsoft Azure Foundations',
                                  'version': '1.2.0', 'reference': '3.5'}],
                                'storageaccount-public-blob-container.json',
                            ),
                        },
                    },
                },
            },
            {
                'provider_code': 'gcp',
                'services': {
                    'cloudstorage': {
                        'findings': {
                            'cloudstorage-bucket-member': _finding(
                                2,
                                2,
                                ['bucket-a', 'bucket-b'],
                                [{'name': 'CIS Google Cloud Platform Foundations',
                                  'version': '1.0.0', 'reference': '5.1'}],
                                'cloudstorage-bucket-member.json',
                            ),
                        },
                    },
                },
            },
        ]

        table = aggregate_cross_cloud_checks(reports)
        self.assertEqual(len(table['checks']), 1)
        row = table['checks'][0]
        self.assertEqual(row['id'], 'storage.public_access')
        self.assertEqual(set(row['providers']), {'aws', 'azure', 'gcp'})
        self.assertEqual(row['providers']['aws']['status'], 'fail')
        self.assertEqual(row['providers']['azure']['status'], 'pass')
        self.assertEqual(row['providers']['gcp']['status'], 'fail')
        self.assertEqual(row['summary'], {
            'status': 'fail',
            'checked': 9,
            'passed': 6,
            'failed': 3,
            'checked_items': 9,
            'passed_items': 6,
            'flagged_items': 3,
        })
        self.assertEqual(row['frameworks'][0]['id'], 'cis')
        self.assertEqual(len(row['frameworks'][0]['controls']), 4)

    def test_report_aggregation_keeps_legacy_findings_unchanged(self):
        report = {
            'provider_code': 'aws',
            'services': {
                's3': {
                    'findings': {
                        's3-bucket-world-policy-star': _finding(
                            1,
                            0,
                            [],
                            rule_id='s3-bucket-world-policy-star.json',
                        ),
                    },
                },
            },
        }
        legacy_findings = copy.deepcopy(report['services']['s3']['findings'])

        result = attach_unified_checks('aws', report)

        self.assertEqual(report['services']['s3']['findings'], legacy_findings)
        self.assertEqual(report['unified_checks'], result)
        self.assertEqual(result['checks'][0]['providers']['aws']['status'], 'pass')
        json.dumps(report)

    def test_rule_metadata_is_discovered_from_existing_report(self):
        report = {
            'provider_code': 'azure',
            'services': {
                'storageaccounts': {
                    'findings': {
                        'custom-finding-key': {
                            **_finding(5, 1, ['container-a']),
                            'unified_check': {'id': 'storage.public_access'},
                        },
                    },
                },
            },
        }

        aggregator = CrossCloudCheckAggregator()
        aggregator.add_report(report)
        row = aggregator.as_table()[0]

        self.assertEqual(row['id'], 'storage.public_access')
        self.assertEqual(row['providers']['azure']['checked'], 5)
        self.assertEqual(row['providers']['azure']['failed'], 1)

    def test_provider_objects_can_be_aggregated_directly(self):
        report = SimpleNamespace(
            provider_code='aws',
            provider_name='Amazon Web Services',
            services={
                's3': {
                    'findings': {
                        's3-bucket-world-policy-star': _finding(
                            1,
                            0,
                            [],
                            rule_id='s3-bucket-world-policy-star.json',
                        ),
                    },
                },
            },
        )

        table = aggregate_cross_cloud_checks([report])
        self.assertEqual(table['providers'][0]['id'], 'aws')
        self.assertEqual(table['checks'][0]['providers']['aws']['status'], 'pass')

    def test_html_table_has_one_column_per_cloud(self):
        aggregator = CrossCloudCheckAggregator()
        aggregator.add_report({
            'provider_code': 'aws',
            'services': {
                's3': {
                    'findings': {
                        's3-bucket-world-policy-star': _finding(
                            1,
                            1,
                            ['bucket-a'],
                            rule_id='s3-bucket-world-policy-star.json',
                        ),
                    },
                },
            },
        })
        aggregator.add_report({
            'provider_code': 'azure',
            'services': {
                'storageaccounts': {
                    'findings': {
                        'storageaccount-public-blob-container': _finding(
                            1,
                            0,
                            [],
                            rule_id='storageaccount-public-blob-container.json',
                        ),
                    },
                },
            },
        })
        aggregator.add_report({
            'provider_code': 'gcp',
            'services': {
                'cloudstorage': {
                    'findings': {
                        'cloudstorage-bucket-member': _finding(
                            1,
                            0,
                            [],
                            rule_id='cloudstorage-bucket-member.json',
                        ),
                    },
                },
            },
        })

        html = aggregator.to_html()
        self.assertIn('>AWS</th>', html)
        self.assertIn('>AZURE</th>', html)
        self.assertIn('>GCP</th>', html)
        self.assertIn('Object storage is not publicly accessible', html)

    def test_table_can_be_filtered_by_compliance_framework(self):
        reports = [{
            'provider_code': 'aws',
            'services': {
                's3': {
                    'findings': {
                        's3-bucket-world-policy-star': _finding(
                            1,
                            0,
                            [],
                            [{'name': 'CIS Amazon Web Services Foundations',
                              'version': '1.2.0', 'reference': '2.3'}],
                        ),
                    },
                },
            },
        }]

        table = aggregate_cross_cloud_checks(reports, framework='CIS', version='1.2.0')
        self.assertEqual(len(table['checks']), 1)
        self.assertEqual(table['checks'][0]['compliance'][0]['framework'], 'cis')

    def test_existing_scoutsuite_result_file_can_be_loaded(self):
        report = {
            'provider_code': 'aws',
            'services': {
                's3': {
                    'findings': {
                        's3-bucket-world-policy-star': _finding(
                            1,
                            1,
                            ['bucket-a'],
                        ),
                    },
                },
            },
        }
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as report_file:
            report_file.write('scoutsuite_results =\n')
            report_file.write(json.dumps(report))
            path = report_file.name
        try:
            self.assertEqual(load_report_file(path), report)
            table = aggregate_report_files([path])
            self.assertEqual(table['checks'][0]['providers']['aws']['status'], 'fail')
        finally:
            os.unlink(path)
