# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for _filter_instrumented_services function."""

from awslabs.cloudwatch_appsignals_mcp_server.audit_utils import _filter_instrumented_services
from unittest.mock import patch


class TestFilterInstrumentedServices:
    """Test _filter_instrumented_services function."""

    def test_filter_instrumented_services_all_instrumented(self):
        """Test filtering when all services are instrumented."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'payment-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED', 'Platform': 'EKS'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'user-service',
                    'Type': 'Service',
                    'Environment': 'staging',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED', 'Platform': 'Lambda'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        assert len(result) == 2
        service_names = [s['KeyAttributes']['Name'] for s in result]
        assert 'payment-service' in service_names
        assert 'user-service' in service_names

    def test_filter_instrumented_services_mixed_instrumentation(self):
        """Test filtering with mix of instrumented and uninstrumented services."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'instrumented-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED', 'Platform': 'EKS'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'uninstrumented-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'UNINSTRUMENTED', 'Platform': 'EKS'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'aws-native-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'AWS_NATIVE', 'Platform': 'Lambda'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'instrumented-service'

    def test_filter_instrumented_services_no_instrumentation_type(self):
        """Test filtering when services have no InstrumentationType."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'service-without-instrumentation',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    {'Platform': 'EKS'}  # No InstrumentationType
                ],
            },
            {
                'KeyAttributes': {
                    'Name': 'service-with-instrumentation',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED', 'Platform': 'EKS'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Services without InstrumentationType should be considered instrumented
        assert len(result) == 2
        service_names = [s['KeyAttributes']['Name'] for s in result]
        assert 'service-without-instrumentation' in service_names
        assert 'service-with-instrumentation' in service_names

    def test_filter_instrumented_services_empty_attribute_maps(self):
        """Test filtering when services have empty AttributeMaps."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'service-empty-attrs',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [],  # Empty list
            },
            {
                'KeyAttributes': {
                    'Name': 'service-no-attrs',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                # No AttributeMaps key
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Services without AttributeMaps should be considered instrumented
        assert len(result) == 2
        service_names = [s['KeyAttributes']['Name'] for s in result]
        assert 'service-empty-attrs' in service_names
        assert 'service-no-attrs' in service_names

    def test_filter_instrumented_services_invalid_service_name(self):
        """Test filtering services with invalid names."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': '',  # Empty name
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'Unknown',  # Invalid name
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Type': 'Service',  # Missing Name
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'valid-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Only the valid service should be included
        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'valid-service'

    def test_filter_instrumented_services_invalid_service_type(self):
        """Test filtering services with invalid types."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'service-wrong-type',
                    'Type': 'NotService',  # Wrong type
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'service-no-type',
                    'Environment': 'prod',
                    # Missing Type
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'valid-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Only the service with correct type should be included
        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'valid-service'

    def test_filter_instrumented_services_multiple_attribute_maps(self):
        """Test filtering with multiple AttributeMaps per service."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'service-multiple-attrs',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    {'Platform': 'EKS'},  # No InstrumentationType
                    {'InstrumentationType': 'UNINSTRUMENTED'},  # This should filter it out
                    {'Other': 'value'},
                ],
            },
            {
                'KeyAttributes': {
                    'Name': 'service-instrumented-only',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    {'InstrumentationType': 'INSTRUMENTED'},  # This should keep it
                    {'Platform': 'EKS'},  # No InstrumentationType in this one
                ],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # First service should be filtered out due to UNINSTRUMENTED
        # Second service should be kept (only has INSTRUMENTED)
        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'service-instrumented-only'

    def test_filter_instrumented_services_non_dict_attribute_map(self):
        """Test filtering with non-dict AttributeMap entries."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'service-with-non-dict-attr',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    'not-a-dict',  # Non-dict entry
                    {'InstrumentationType': 'INSTRUMENTED'},
                ],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Should handle non-dict entries gracefully and include the service
        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'service-with-non-dict-attr'

    def test_filter_instrumented_services_empty_input(self):
        """Test filtering with empty input."""
        result = _filter_instrumented_services([])
        assert len(result) == 0

    def test_filter_instrumented_services_missing_key_attributes(self):
        """Test filtering services without KeyAttributes."""
        all_services = [
            {
                # Missing KeyAttributes
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {},  # Empty KeyAttributes
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'valid-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Only the service with valid KeyAttributes should be included
        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'valid-service'

    @patch('awslabs.cloudwatch_appsignals_mcp_server.audit_utils.logger')
    def test_filter_instrumented_services_logging(self, mock_logger):
        """Test that filtering logs appropriate debug messages."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'instrumented-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'uninstrumented-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'UNINSTRUMENTED'}],
            },
            {
                'KeyAttributes': {
                    'Name': '',  # Invalid name
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Verify logging calls
        assert mock_logger.debug.call_count >= 3  # At least one call per service
        assert mock_logger.info.call_count == 1  # Summary log

        # Check that the summary log includes correct counts
        summary_call = mock_logger.info.call_args[0][0]
        assert '1 instrumented out of 3 total services' in summary_call

        # Verify result
        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'instrumented-service'

    def test_filter_instrumented_services_case_sensitivity(self):
        """Test that InstrumentationType filtering is case-sensitive."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'service-lowercase',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    {'InstrumentationType': 'uninstrumented'}  # lowercase
                ],
            },
            {
                'KeyAttributes': {
                    'Name': 'service-uppercase',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    {'InstrumentationType': 'UNINSTRUMENTED'}  # uppercase
                ],
            },
            {
                'KeyAttributes': {
                    'Name': 'service-mixed-case',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    {'InstrumentationType': 'Uninstrumented'}  # mixed case
                ],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Only exact case matches should be filtered out
        # lowercase and mixed case should be kept (not exact matches)
        assert len(result) == 2
        service_names = [s['KeyAttributes']['Name'] for s in result]
        assert 'service-lowercase' in service_names
        assert 'service-mixed-case' in service_names
        assert 'service-uppercase' not in service_names

    def test_filter_instrumented_services_aws_native_filtering(self):
        """Test that AWS_NATIVE services are filtered out."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'aws-native-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'AWS_NATIVE'}],
            },
            {
                'KeyAttributes': {
                    'Name': 'regular-service',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [{'InstrumentationType': 'INSTRUMENTED'}],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # AWS_NATIVE should be filtered out
        assert len(result) == 1
        assert result[0]['KeyAttributes']['Name'] == 'regular-service'

    def test_filter_instrumented_services_break_on_first_uninstrumented(self):
        """Test that filtering breaks on first UNINSTRUMENTED/AWS_NATIVE found."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'service-with-mixed-attrs',
                    'Type': 'Service',
                    'Environment': 'prod',
                },
                'AttributeMaps': [
                    {'Platform': 'EKS'},  # No InstrumentationType
                    {'InstrumentationType': 'UNINSTRUMENTED'},  # This should cause filtering
                    {'InstrumentationType': 'INSTRUMENTED'},  # This should be ignored
                ],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Service should be filtered out due to UNINSTRUMENTED (breaks on first match)
        assert len(result) == 0

    def test_filter_instrumented_services_real_world_scenario(self):
        """Test filtering with realistic service data."""
        all_services = [
            {
                'KeyAttributes': {
                    'Name': 'payment-gateway',
                    'Type': 'Service',
                    'Environment': 'eks:production/default',
                },
                'AttributeMaps': [
                    {
                        'InstrumentationType': 'INSTRUMENTED',
                        'Platform': 'EKS',
                        'Application': 'payment-app',
                    }
                ],
            },
            {
                'KeyAttributes': {
                    'Name': 'user-auth-lambda',
                    'Type': 'Service',
                    'Environment': 'lambda',
                },
                'AttributeMaps': [
                    {
                        'InstrumentationType': 'INSTRUMENTED',
                        'Platform': 'Lambda',
                        'Runtime': 'nodejs18.x',
                    }
                ],
            },
            {
                'KeyAttributes': {
                    'Name': 'legacy-service',
                    'Type': 'Service',
                    'Environment': 'ec2:legacy',
                },
                'AttributeMaps': [
                    {
                        'InstrumentationType': 'UNINSTRUMENTED',
                        'Platform': 'EC2',
                        'Reason': 'Legacy system without instrumentation',
                    }
                ],
            },
            {
                'KeyAttributes': {
                    'Name': 'aws-s3-service',
                    'Type': 'Service',
                    'Environment': 'aws:s3',
                },
                'AttributeMaps': [
                    {
                        'InstrumentationType': 'AWS_NATIVE',
                        'Platform': 'AWS',
                        'ServiceType': 'S3',
                    }
                ],
            },
        ]

        result = _filter_instrumented_services(all_services)

        # Only instrumented services should remain
        assert len(result) == 2
        service_names = [s['KeyAttributes']['Name'] for s in result]
        assert 'payment-gateway' in service_names
        assert 'user-auth-lambda' in service_names
        assert 'legacy-service' not in service_names
        assert 'aws-s3-service' not in service_names
