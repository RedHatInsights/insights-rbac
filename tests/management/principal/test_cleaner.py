#
# Copyright 2019 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Test the principal cleaner."""
from functools import partial
import uuid

from unittest.mock import MagicMock, patch

from django.test import override_settings
from rest_framework import status

from management.group.definer import seed_group
from management.group.model import Group
from management.policy.model import Policy
from management.principal.cleaner import clean_tenant_principals
from management.principal.model import Principal
from management.principal.cleaner import process_principal_events_from_umb
from management.principal.proxy import external_principal_to_user
from management.tenant_mapping.model import TenantMapping
from management.tenant_service import get_tenant_bootstrap_service
from management.workspace.model import Workspace
from api.models import Tenant
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    RelationTuple,
    all_of,
    relation,
    resource,
    subject,
)
from tests.identity_request import IdentityRequest


class PrincipalCleanerTests(IdentityRequest):
    """Test the principal cleaner functions."""

    def setUp(self):
        """Set up the principal cleaner tests."""
        super().setUp()
        self.group = Group(name="groupA", tenant=self.tenant)
        self.group.save()

    def test_principal_cleanup_none(self):
        """Test that we can run a principal clean up on a tenant with no principals."""
        try:
            clean_tenant_principals(self.tenant)
        except Exception:
            self.fail(msg="clean_tenant_principals encountered an exception")
        self.assertEqual(Principal.objects.count(), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_200_OK, "data": []},
    )
    def test_principal_cleanup_skip_cross_account_principals(self, mock_request):
        """Test that principal clean up on a tenant will skip cross account principals."""
        Principal.objects.create(username="user1", tenant=self.tenant)
        Principal.objects.create(username="CAR", cross_account=True, tenant=self.tenant)
        self.assertEqual(Principal.objects.count(), 2)

        try:
            clean_tenant_principals(self.tenant)
        except Exception:
            self.fail(msg="clean_tenant_principals encountered an exception")
        self.assertEqual(Principal.objects.count(), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_200_OK, "data": []},
    )
    def test_principal_cleanup_skips_service_account_principals(self, mock_request):
        """Test that principal clean up on a tenant will skip service account principals."""
        # Create a to-be-removed user principal and a service account that should be left untouched.
        service_account_client_id = str(uuid.uuid4())
        Principal.objects.create(username="regular user", tenant=self.tenant)
        Principal.objects.create(
            username=f"service-account-{service_account_client_id}",
            service_account_id=service_account_client_id,
            tenant=self.tenant,
            type="service-account",
        )
        self.assertEqual(Principal.objects.count(), 2)

        try:
            clean_tenant_principals(self.tenant)
        except Exception:
            self.fail(msg="clean_tenant_principals encountered an exception")

        # Assert that the only principal left for the tenant is the service account, which should have been left
        # untouched.
        self.assertEqual(Principal.objects.count(), 1)

        service_account = Principal.objects.all().filter(type="service-account").first()
        self.assertEqual(service_account.service_account_id, service_account_client_id)
        self.assertEqual(service_account.type, "service-account")
        self.assertEqual(service_account.username, f"service-account-{service_account_client_id}")

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_200_OK, "data": []},
    )
    def test_principal_cleanup_principal_in_group(self, mock_request):
        """Test that we can run a principal clean up on a tenant with a principal in a group."""
        self.principal = Principal(username="user1", tenant=self.tenant)
        self.principal.save()
        self.group.principals.add(self.principal)
        self.group.save()
        try:
            clean_tenant_principals(self.tenant)
        except Exception:
            self.fail(msg="clean_tenant_principals encountered an exception")
        self.assertEqual(Principal.objects.count(), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_200_OK, "data": []},
    )
    def test_principal_cleanup_principal_not_in_group(self, mock_request):
        """Test that we can run a principal clean up on a tenant with a principal not in a group."""
        self.principal = Principal(username="user1", tenant=self.tenant)
        self.principal.save()
        try:
            clean_tenant_principals(self.tenant)
        except Exception:
            self.fail(msg="clean_tenant_principals encountered an exception")
        self.assertEqual(Principal.objects.count(), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_200_OK, "data": [{"username": "user1"}]},
    )
    def test_principal_cleanup_principal_exists(self, mock_request):
        """Test that we can run a principal clean up on a tenant with an existing principal."""
        self.principal = Principal(username="user1", tenant=self.tenant)
        self.principal.save()
        try:
            clean_tenant_principals(self.tenant)
        except Exception:
            self.fail(msg="clean_tenant_principals encountered an exception")
        self.assertEqual(Principal.objects.count(), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_504_GATEWAY_TIMEOUT},
    )
    def test_principal_cleanup_principal_error(self, mock_request):
        """Test that we can handle a principal clean up with an unexpected error from proxy."""
        self.principal = Principal(username="user1", tenant=self.tenant)
        self.principal.save()
        try:
            clean_tenant_principals(self.tenant)
        except Exception:
            self.fail(msg="clean_tenant_principals encountered an exception")
        self.assertEqual(Principal.objects.count(), 1)


FRAME_BODY = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<CanonicalMessage xmlns="http://esb.redhat.com/Canonical/6">\n    '
    b"<Header>\n        <System>WEB</System>\n        <Operation>update</Operation>\n        <Type>User</Type>\n        "
    b"<InstanceId>660a018a6d336076b5b57fff</InstanceId>\n        <Timestamp>2024-03-31T20:36:27.820</Timestamp>\n    </Header>\n    "
    b"<Payload>\n        <Sync>\n            <User>\n                <CreatedDate>2024-02-16T02:57:51.738</CreatedDate>\n                "
    b"<LastUpdatedDate>2024-02-21T06:47:24.672</LastUpdatedDate>\n                <Identifiers>\n                    "
    b'<Identifier system="WEB" entity-name="User" qualifier="id">56780000</Identifier>\n                   '
    b'<Reference system="WEB" entity-name="Customer" qualifier="id">17685860</Reference>\n                    '
    b'<Reference system="EBS" entity-name="Account" qualifier="number">11111111</Reference>\n                '
    b'</Identifiers>\n                <Status primary="true">\n                    <State>Inactive</State>\n                '
    b"</Status>\n                <Person>\n                    <FirstName>Test</FirstName>\n                    "
    b"<LastName>Principal</LastName>\n                    <Salutation>Mr.</Salutation>\n                    <Title>QE</Title>\n                    "
    b"<Credentials>\n                        <Login>principal-test</Login>\n                    </Credentials>\n                "
    b"</Person>\n                <Company>\n                    <Name>Shakespeare Birthplace Trust</Name>\n                "
    b"</Company>\n                <Address>\n                    <Identifiers>\n                        <AuthoringOperatingUnit>\n"
    b"<Number>103</Number>\n                        </AuthoringOperatingUnit>\n                        "
    b'<Identifier system="WEB" entity-name="Address" entity-type="Customer Site" qualifier="id">33535807_SITE</Identifier>\n                    '
    b'</Identifiers>\n                    <Status primary="true">\n                        <State>Inactive</State>\n                    '
    b'</Status>\n                    <Line number="1">100 E. Davie St.</Line>\n                    <City>Raleigh</City>\n                    '
    b'<Subdivision type="County">Wake</Subdivision>\n                    <State>NC</State>\n                    '
    b"<CountryISO2Code>US</CountryISO2Code>\n                    <PostalCode>27601</PostalCode>\n                </Address>\n                "
    b'<Phone type="Gen" primary="true">\n                    <Identifiers>\n                        '
    b'<Identifier system="WEB" entity-name="Phone" qualifier="id">56780000_IPHONE</Identifier>\n                    '
    b"</Identifiers>\n                    <Number>1234567890</Number>\n                    <RawNumber>1234567890</RawNumber>\n                "
    b'</Phone>\n                <Email primary="true">\n                    <Identifiers>\n                        '
    b'<Identifier system="WEB" entity-name="Email" qualifier="id">56780000_IEMAIL</Identifier>\n                    '
    b"</Identifiers>\n                    <EmailAddress>test@email.com</EmailAddress>\n                </Email>\n                "
    b"<UserMembership>\n                    <Name>admin:org:all</Name>\n                </UserMembership>\n                "
    b"<UserMembership>\n                    <Name>foo</Name>\n                </UserMembership>\n                "
    b"<UserPrivilege>\n                    <Label>portal_system_management</Label>\n                    "
    b"<Description>Customer Portal: System Management</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n                <UserPrivilege>\n                    <Label>portal_download</Label>\n                    "
    b"<Description>Customer Portal: Download Software and Updates</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n                <UserPrivilege>\n                    <Label>portal_manage_subscriptions</Label>\n                    "
    b"<Description>Customer Portal: Manage Subscriptions</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n                <UserPrivilege>\n                    <Label>portal_manage_cases</Label>\n                    "
    b"<Description>Customer Portal: Manage Support Cases</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n            </User>\n        </Sync>\n    </Payload>\n</CanonicalMessage>\n"
)

FRAME_BODY_CREATION = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<CanonicalMessage xmlns="http://esb.redhat.com/Canonical/6">\n    '
    b"<Header>\n        <System>WEB</System>\n        <Operation>insert</Operation>\n        <Type>User</Type>\n        "
    b"<InstanceId>660a018a6d336076b5b57fff</InstanceId>\n        <Timestamp>2024-03-31T20:36:27.820</Timestamp>\n    </Header>\n    "
    b"<Payload>\n        <Sync>\n            <User>\n                <CreatedDate>2024-02-16T02:57:51.738</CreatedDate>\n                "
    b"<LastUpdatedDate>2024-02-21T06:47:24.672</LastUpdatedDate>\n                <Identifiers>\n                    "
    b'<Identifier system="WEB" entity-name="User" qualifier="id">56780000</Identifier>\n                   '
    b'<Reference system="WEB" entity-name="Customer" qualifier="id">17685860</Reference>\n                    '
    b'<Reference system="EBS" entity-name="Account" qualifier="number">11111111</Reference>\n                '
    b'</Identifiers>\n                <Status primary="true">\n                    <State>Active</State>\n                '
    b"</Status>\n                <Person>\n                    <FirstName>Test</FirstName>\n                    "
    b"<LastName>Principal</LastName>\n                    <Salutation>Mr.</Salutation>\n                    <Title>QE</Title>\n                    "
    b"<Credentials>\n                        <Login>principal-test</Login>\n                    </Credentials>\n                "
    b"</Person>\n                <Company>\n                    <Name>Shakespeare Birthplace Trust</Name>\n                "
    b"</Company>\n                <Address>\n                    <Identifiers>\n                        <AuthoringOperatingUnit>\n"
    b"<Number>103</Number>\n                        </AuthoringOperatingUnit>\n                        "
    b'<Identifier system="WEB" entity-name="Address" entity-type="Customer Site" qualifier="id">33535807_SITE</Identifier>\n                    '
    b'</Identifiers>\n                    <Status primary="true">\n                        <State>Inactive</State>\n                    '
    b'</Status>\n                    <Line number="1">100 E. Davie St.</Line>\n                    <City>Raleigh</City>\n                    '
    b'<Subdivision type="County">Wake</Subdivision>\n                    <State>NC</State>\n                    '
    b"<CountryISO2Code>US</CountryISO2Code>\n                    <PostalCode>27601</PostalCode>\n                </Address>\n                "
    b'<Phone type="Gen" primary="true">\n                    <Identifiers>\n                        '
    b'<Identifier system="WEB" entity-name="Phone" qualifier="id">56780000_IPHONE</Identifier>\n                    '
    b"</Identifiers>\n                    <Number>1234567890</Number>\n                    <RawNumber>1234567890</RawNumber>\n                "
    b'</Phone>\n                <Email primary="true">\n                    <Identifiers>\n                        '
    b'<Identifier system="WEB" entity-name="Email" qualifier="id">56780000_IEMAIL</Identifier>\n                    '
    b"</Identifiers>\n                    <EmailAddress>test@email.com</EmailAddress>\n                </Email>\n                "
    b"<UserMembership>\n                    <Name>admin:org:all</Name>\n                </UserMembership>\n                "
    b"<UserMembership>\n                    <Name>foo</Name>\n                </UserMembership>\n                "
    b"<UserPrivilege>\n                    <Label>portal_system_management</Label>\n                    "
    b"<Description>Customer Portal: System Management</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n                <UserPrivilege>\n                    <Label>portal_download</Label>\n                    "
    b"<Description>Customer Portal: Download Software and Updates</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n                <UserPrivilege>\n                    <Label>portal_manage_subscriptions</Label>\n                    "
    b"<Description>Customer Portal: Manage Subscriptions</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n                <UserPrivilege>\n                    <Label>portal_manage_cases</Label>\n                    "
    b"<Description>Customer Portal: Manage Support Cases</Description>\n                    <Privileged>Y</Privileged>\n                "
    b"</UserPrivilege>\n            </User>\n        </Sync>\n    </Payload>\n</CanonicalMessage>\n"
)


class PrincipalUMBTests(IdentityRequest):
    """Test the principal processor functions."""

    def setUp(self):
        """Set up the principal processor tests."""
        super().setUp()
        self.principal_name = "principal-test"
        self.principal_user_id = "56780000"
        self.tenant.org_id = "17685860"
        self.tenant.save()
        self.group = Group(name="groupA", tenant=self.tenant)
        self.group.save()

    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_principal_cleanup_none(self, client_mock):
        """Test that we can run a principal clean up with no messages."""
        client_mock.canRead.return_value = False
        process_principal_events_from_umb()

        client_mock.receiveFrame.assert_not_called()
        client_mock.disconnect.assert_called_once()

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={
            "status_code": status.HTTP_200_OK,
            "data": [],
        },
    )
    @patch("management.group.model.AccessCache")
    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_cleanup_principal_in_or_not_in_group(self, client_mock, cache_class, proxy_mock):
        """Test that we can run a principal clean up on a tenant with a principal in a group."""
        principal_name = "principal-test"
        self.principal = Principal(username=principal_name, tenant=self.tenant, user_id="56780000")
        self.principal.save()
        self.group.principals.add(self.principal)
        self.group.save()

        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY)
        cache_mock = MagicMock()
        cache_class.return_value = cache_mock
        process_principal_events_from_umb()

        client_mock.receiveFrame.assert_called_once()
        client_mock.disconnect.assert_called_once()
        client_mock.ack.assert_called_once()
        self.assertFalse(Principal.objects.filter(username=principal_name).exists())
        self.group.refresh_from_db()
        self.assertFalse(self.group.principals.all())
        cache_mock.delete_policy.assert_called_once_with(self.principal.uuid)

        # When principal not in group
        self.principal = Principal(username=principal_name, tenant=self.tenant, user_id="56780000")
        self.principal.save()
        client_mock.canRead.side_effect = [True, False]
        client_mock.ack.reset_mock()
        process_principal_events_from_umb()
        self.assertFalse(Principal.objects.filter(username=principal_name).exists())
        client_mock.ack.assert_called_once()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_cleanup_principal_does_not_exist(self, client_mock, proxy_mock):
        """Test that can run a principal clean up with a principal does not exist."""
        principal_name = "principal-keep"
        self.principal = Principal(username=principal_name, tenant=self.tenant)
        self.principal.save()

        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY)
        process_principal_events_from_umb()

        client_mock.ack.assert_called_once()
        self.assertTrue(Principal.objects.filter(username=principal_name).exists())

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_cleanup_principal_does_not_exist_no_tenant(self, client_mock, proxy_mock):
        """Test that can run a principal clean up with a user whose Tenant does not exist."""
        principal_name = "principal-keep"
        self.tenant.delete()

        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY)
        process_principal_events_from_umb()

        client_mock.ack.assert_called_once()
        self.assertFalse(Principal.objects.filter(username=principal_name).exists())

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_cleanup_same_principal_name_in_multiple_tenants(self, client_mock, proxy_mock):
        """Test that can run a principal clean up with a principal that have multiple tenants."""
        another_tenant = Tenant.objects.create(
            tenant_name="another", account_id="11111112", org_id="17685861", ready=True
        )
        self.principal = Principal.objects.create(username=self.principal_name, user_id="56780000", tenant=self.tenant)
        Principal.objects.create(username=self.principal_name, user_id="12340000", tenant=another_tenant)
        self.assertEqual(Principal.objects.filter(username=self.principal_name).count(), 2)

        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY)
        process_principal_events_from_umb()

        client_mock.receiveFrame.assert_called_once()
        client_mock.disconnect.assert_called_once()
        client_mock.ack.assert_called_once()
        self.assertFalse(Principal.objects.filter(username=self.principal_name, tenant=self.tenant).exists())
        self.assertTrue(Principal.objects.filter(username=self.principal_name, tenant=another_tenant).exists())

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "user_id": 56780000,
                    "org_id": "17685860",
                    "username": "principal-test",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "is_org_admin": False,
                    "is_active": True,
                }
            ],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    @override_settings(PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB=True, V1_BOOTSTRAP_ADD_USER_ID=True)
    def test_principal_creation_event_does_not_create_principal(self, client_mock, proxy_mock):
        """Test that we can run principal creation event."""
        public_tenant = Tenant.objects.get(tenant_name="public")
        Group.objects.create(name="default", platform_default=True, tenant=public_tenant)
        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY_CREATION)
        Tenant.objects.get(org_id="17685860").delete()
        process_principal_events_from_umb()

        client_mock.receiveFrame.assert_called_once()
        client_mock.disconnect.assert_called_once()
        client_mock.ack.assert_called_once()
        self.assertTrue(Tenant.objects.filter(org_id="17685860").exists())
        self.assertFalse(Principal.objects.filter(user_id=self.principal_user_id).exists())

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "user_id": 56780000,
                    "org_id": "17685860",
                    "username": "principal-test",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "is_org_admin": False,
                    "is_active": True,
                }
            ],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    @override_settings(PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB=True, V1_BOOTSTRAP_ADD_USER_ID=True)
    def test_principal_creation_event_updates_existing_principal(self, client_mock, proxy_mock):
        """Test that we can run principal creation event."""
        public_tenant = Tenant.objects.get(tenant_name="public")
        Group.objects.create(name="default", platform_default=True, tenant=public_tenant)
        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY_CREATION)
        tenant = Tenant.objects.get(org_id="17685860")
        Principal.objects.create(tenant=tenant, username="principal-test")
        process_principal_events_from_umb()

        client_mock.receiveFrame.assert_called_once()
        client_mock.disconnect.assert_called_once()
        client_mock.ack.assert_called_once()
        self.assertTrue(Tenant.objects.filter(org_id="17685860").exists())
        self.assertTrue(Principal.objects.filter(user_id=self.principal_user_id).exists())


@override_settings(V2_BOOTSTRAP_TENANT=True, PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB=True)
class PrincipalUMBTestsWithV2TenantBootstrap(PrincipalUMBTests):
    """Test the principal processor functions with V2 tenant bootstrap enabled."""

    _tuples: InMemoryTuples

    def setUp(self):
        super().setUp()
        seed_group()
        self._tuples = InMemoryTuples()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "user_id": "56780000",
                    "org_id": "17685860",
                    "username": "principal-test",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "is_org_admin": False,
                    "is_active": True,
                }
            ],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    @override_settings(PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB=False)
    def test_principal_creation_event_disabled(self, client_mock, proxy_mock):
        """Test that we can run principal creation event."""
        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY_CREATION)
        Tenant.objects.get(org_id="17685860").delete()
        process_principal_events_from_umb()

        client_mock.receiveFrame.assert_called_once()
        client_mock.disconnect.assert_called_once()
        client_mock.ack.assert_called_once()
        self.assertFalse(Tenant.objects.filter(org_id="17685860").exists())
        self.assertFalse(Principal.objects.filter(user_id=self.principal_user_id).exists())

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "user_id": "56780000",
                    "org_id": "17685860",
                    "username": "principal-test",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "is_org_admin": False,
                    "is_active": True,
                }
            ],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_principal_creation_event_bootstraps_new_tenant(self, client_mock, proxy_mock):
        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY_CREATION)
        Tenant.objects.get(org_id="17685860").delete()

        with patch(
            "management.principal.cleaner.OutboxReplicator", new=partial(InMemoryRelationReplicator, self._tuples)
        ):
            process_principal_events_from_umb()

            client_mock.receiveFrame.assert_called_once()
            client_mock.disconnect.assert_called_once()
            client_mock.ack.assert_called_once()

            self.assertTenantBootstrappedByOrgId("17685860")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "user_id": "56780000",
                    "org_id": "17685860",
                    "username": "principal-test",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "is_org_admin": False,
                    "is_active": True,
                }
            ],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_principal_creation_event_bootstraps_existing_tenants(self, client_mock, proxy_mock):
        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY_CREATION)

        with patch(
            "management.principal.cleaner.OutboxReplicator", new=partial(InMemoryRelationReplicator, self._tuples)
        ):
            process_principal_events_from_umb()

            client_mock.receiveFrame.assert_called_once()
            client_mock.disconnect.assert_called_once()
            client_mock.ack.assert_called_once()

            self.assertTenantBootstrappedByOrgId("17685860")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "user_id": "56780000",
                    "org_id": "17685860",
                    "username": "principal-test",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "is_org_admin": False,
                    "is_active": True,
                }
            ],
        },
    )
    @patch("management.principal.cleaner.UMB_CLIENT")
    def test_principal_creation_event_does_not_bootstrap_already_bootstraped_tenant(self, client_mock, proxy_mock):
        client_mock.canRead.side_effect = [True, False]
        client_mock.receiveFrame.return_value = MagicMock(body=FRAME_BODY_CREATION)

        bootstrap_service = get_tenant_bootstrap_service(InMemoryRelationReplicator(self._tuples))
        user = external_principal_to_user(proxy_mock.return_value["data"][0])
        bootstrap_service.update_user(user)

        self._tuples.clear()

        with patch(
            "management.principal.cleaner.OutboxReplicator", new=partial(InMemoryRelationReplicator, self._tuples)
        ):
            process_principal_events_from_umb()

            client_mock.receiveFrame.assert_called_once()
            client_mock.disconnect.assert_called_once()
            client_mock.ack.assert_called_once()

            mapping = TenantMapping.objects.get(tenant__org_id="17685860")
            all_tuples = self._tuples.find_tuples()

            # Should only have one tuple to ensure the user is in the default group
            self.assertEqual(
                all_tuples,
                [
                    RelationTuple(
                        resource_type_namespace="rbac",
                        resource_type_name="group",
                        resource_id=str(mapping.default_group_uuid),
                        relation="member",
                        subject_type_namespace="rbac",
                        subject_type_name="principal",
                        subject_id=f"redhat/{self.principal_user_id}",
                        subject_relation="",
                    )
                ],
            )

    def assertTenantBootstrappedByOrgId(self, org_id: str):
        tenant = Tenant.objects.get(org_id=org_id)
        self.assertIsNotNone(tenant)
        mapping = TenantMapping.objects.get(tenant=tenant)
        self.assertIsNotNone(mapping)
        workspaces = list(Workspace.objects.filter(tenant=tenant))
        self.assertEqual(len(workspaces), 2)
        default = Workspace.objects.get(type=Workspace.Types.DEFAULT, tenant=tenant)
        self.assertIsNotNone(default)
        root = Workspace.objects.get(type=Workspace.Types.ROOT, tenant=tenant)
        self.assertIsNotNone(root)

        platform_default_policy = Policy.objects.get(group=Group.objects.get(platform_default=True))
        admin_default_policy = Policy.objects.get(group=Group.objects.get(admin_default=True))

        self.assertEqual(
            1,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.uuid),
                    relation("binding"),
                    subject("rbac", "role_binding", mapping.default_role_binding_uuid),
                )
            ),
        )
        self.assertEqual(
            1,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                    relation("subject"),
                    subject("rbac", "group", mapping.default_group_uuid, "member"),
                )
            ),
        )
        self.assertEqual(
            1,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                    relation("role"),
                    subject("rbac", "role", platform_default_policy.uuid),
                )
            ),
        )

        self.assertEqual(
            1,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.uuid),
                    relation("binding"),
                    subject("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                )
            ),
        )
        self.assertEqual(
            1,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                    relation("subject"),
                    subject("rbac", "group", mapping.default_admin_group_uuid, "member"),
                )
            ),
        )
        self.assertEqual(
            1,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                    relation("role"),
                    subject("rbac", "role", admin_default_policy.uuid),
                )
            ),
        )
