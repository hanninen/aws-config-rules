import sys
import unittest
try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::Role'

#############
# Main Code #
#############

config_client_mock = MagicMock(name='config')
sts_client_mock = MagicMock(name='sts')
ssm_client_mock = MagicMock(name='ssm')

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'ssm':
            return ssm_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_ROLE_ACCOUNT_TRUST_WHITELISTED')

class Principals(unittest.TestCase):

    rule_parameters = '{"SSM_ROLE_ARN":"arn:aws:iam::555555555555:role/config-ssm-param-store-role"}'

    # def setUp(self):
    #    pass

    # def test_sample(self):
    #    self.assertTrue(True)

    def test_principal_is_aws_account(self):
        parameter = {
            "Name": "/IAM/Roles/Whitelist/123456789012/mock-role",
            "Type": "StringList",
            "Value": "210987654321",
            "Version": 2,
            "LastModifiedDate": "2018-01-01 01:01:01.000001+03:00",
            "ARN": "arn:aws:ssm:us-east-1:555555555555:parameter/IAM/Roles/Whitelist/123456789012/mock-role"
        }
        ssm_mock(parameter)

        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn:aws:iam::210987654321:root%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'

        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role', annotation="AWS account trust whitelisted: ['210987654321']"))
        assert_successful_evaluation(self, response, resp_expected)

    def test_principal_is_aws_service(self):
        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22ec2.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_principal_is_federated(self):
        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Federated%22%3A%22arn:aws:iam::210987654321:saml-provider/idp%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role'))
        assert_successful_evaluation(self, response, resp_expected)

class AWSAccountTrusts(unittest.TestCase):

    rule_parameters = '{"SSM_ROLE_ARN":"arn:aws:iam::555555555555:role/config-ssm-param-store-role"}'

    def test_single_aws_account_trusted(self):
        parameter = {
            "Name": "/IAM/Roles/Whitelist/123456789012/mock-role",
            "Type": "StringList",
            "Value": "210987654321",
            "Version": 2,
            "LastModifiedDate": "2018-01-01 01:01:01.000001+03:00",
            "ARN": "arn:aws:ssm:us-east-1:555555555555:parameter/IAM/Roles/Whitelist/123456789012/mock-role"
        }
        ssm_mock(parameter)

        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn:aws:iam::210987654321:root%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'

        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role', annotation="AWS account trust whitelisted: ['210987654321']"))
        assert_successful_evaluation(self, response, resp_expected)

    def test_multiple_aws_accounts_trusted(self):
        parameter = {
            "Name": "/IAM/Roles/Whitelist/123456789012/mock-role",
            "Type": "StringList",
            "Value": "210987654321,123456789012",
            "Version": 2,
            "LastModifiedDate": "2018-01-01 01:01:01.000001+03:00",
            "ARN": "arn:aws:ssm:us-east-1:555555555555:parameter/IAM/Roles/Whitelist/123456789012/mock-role"
        }
        ssm_mock(parameter)

        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%5B%22arn%3Aaws%3Aiam%3A%3A210987654321%3Aroot%22%2C%20%20%20%20%22arn%3Aaws%3Aiam%3A%3A123456789012%3Aroot%22%5D%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'

        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append((build_expected_response('COMPLIANT', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role', annotation="AWS account trust whitelisted: ['210987654321', '123456789012']")))
        assert_successful_evaluation(self, response, resp_expected)

    def test_no_aws_accounts_whitelisted(self):
        parameter = {
            "Name": "/IAM/Roles/Whitelist/123456789012/mock-role",
            "Type": "StringList",
            "Value": "",
            "Version": 2,
            "LastModifiedDate": "2018-01-01 01:01:01.000001+03:00",
            "ARN": "arn:aws:ssm:us-east-1:555555555555:parameter/IAM/Roles/Whitelist/123456789012/mock-role"
        }
        ssm_mock(parameter)

        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn:aws:iam::210987654321:root%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'

        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role', annotation="Unauthorized AWS account trust detected: ['210987654321']"))
        assert_successful_evaluation(self, response, resp_expected)

    def one_aws_account_trusted_multiple_whitelisted(self):
        parameter = {
            "Name": "/IAM/Roles/Whitelist/123456789012/mock-role",
            "Type": "StringList",
            "Value": "210987654321,123456789012",
            "Version": 2,
            "LastModifiedDate": "2018-01-01 01:01:01.000001+03:00",
            "ARN": "arn:aws:ssm:us-east-1:555555555555:parameter/IAM/Roles/Whitelist/123456789012/mock-role"
        }
        ssm_mock(parameter)

        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn:aws:iam::210987654321:root%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'

        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role', annotation="AWS account trust whitelisted: ['210987654321']"))
        assert_successful_evaluation(self, response, resp_expected)

    def multiple_aws_accounts_trusted_one_whitelisted(self):
        parameter = {
            "Name": "/IAM/Roles/Whitelist/123456789012/mock-role",
            "Type": "StringList",
            "Value": "210987654321",
            "Version": 2,
            "LastModifiedDate": "2018-01-01 01:01:01.000001+03:00",
            "ARN": "arn:aws:ssm:us-east-1:555555555555:parameter/IAM/Roles/Whitelist/123456789012/mock-role"
        }
        ssm_mock(parameter)

        invoking_event = '{"configurationItem":{"awsAccountId": "123456789012", "relatedEvents":[],"relationships":[],"configuration":{"roleName": "mock-role", "assumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%5B%22arn:aws:iam::210987654321:root%22%arn:aws:iam::123456789012:root%22%5D,%227D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D" },"tags":{},"configurationItemCaptureTime":"2018-01-01T01:01:01.001Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"AROAAAAAAAAAAAAAAAAAA","resourceName":"mock-role","ARN":"arn:aws:iam::123456789012:role/mock-role"},"notificationCreationTime":"2018-01-01T01:01:01.001Z","messageType":"ConfigurationItemChangeNotification"}'

        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AROAAAAAAAAAAAAAAAAAA', 'AWS::IAM::Role', annotation='External AWS account trust whitelisted'))
        assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    if not annotation:
        return {
            'ComplianceType': compliance_type,
            'ComplianceResourceId': compliance_resource_id,
            'ComplianceResourceType': compliance_resource_type
            }
    return {
        'ComplianceType': compliance_type,
        'ComplianceResourceId': compliance_resource_id,
        'ComplianceResourceType': compliance_resource_type,
        'Annotation': annotation
        }

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                testClass.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(testClass, response, customerErrorCode=None, customerErrorMessage=None):
    if customerErrorCode:
        testClass.assertEqual(customerErrorCode, response['customerErrorCode'])
    if customerErrorMessage:
        testClass.assertEqual(customerErrorMessage, response['customerErrorMessage'])
    testClass.assertTrue(response['customerErrorCode'])
    testClass.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        testClass.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        testClass.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    sts_client_mock.reset_mock(return_value=True)
    sts_client_mock.assume_role = MagicMock(return_value=assume_role_response)

def ssm_mock(parameter):
    get_parameter_response = {
        "Parameter": {
            "Name": parameter['Name'],
            "Type": parameter['Type'],
            "Value": parameter['Value'],
            "Version": parameter['Version'],
            "LastModifiedDate": parameter['LastModifiedDate'],
            "ARN": parameter['ARN']
        }}
    ssm_client_mock.reset_mock(return_value=True)
    ssm_client_mock.get_parameter = MagicMock(return_value=get_parameter_response)

##################
# Common Testing #
##################

# class TestStsErrors(unittest.TestCase):
#
#     def test_sts_unknown_error(self):
#         rule.ASSUME_ROLE_MODE = True
#         sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
#             {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
#         response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
#         assert_customer_error_response(
#             self, response, 'InternalError', 'InternalError')
#
#     def test_sts_access_denied(self):
#         rule.ASSUME_ROLE_MODE = True
#         sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
#             {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
#         response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
#         assert_customer_error_response(
#             self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
