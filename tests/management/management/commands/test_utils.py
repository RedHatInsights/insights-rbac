from unittest.mock import mock_open, patch

from django.db.utils import IntegrityError
from django.test import TestCase

from api.models import Tenant
from management.group.view import SERVICE_ACCOUNT_USERNAME_FORMAT
from management.management.commands.utils import (
    populate_tenant_user_data,
    populate_service_account_data,
    process_batch,
)
from management.models import Principal


class TestProcessBatch(TestCase):
    @patch("management.management.commands.utils.process_batch")
    def test_populate_tenant_user_data(self, batch_mock):
        mock_file_content = """orgs_info[0].id,orgs_info[0].perm[0],principals[0],_id
1000000,admin:org:all,test_user_1,1
10000001,admin:org:all,test_user_2,2
10000002,,test_user_3,3
10000003,,test_user_4,4
"""

        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            populate_tenant_user_data("file_name", start_line=2, batch_size=2)

        self.assertEqual(
            batch_mock.call_args_list[0][0][0],
            [
                ("10000001", True, "test_user_2", "2"),
                ("10000002", False, "test_user_3", "3"),
            ],
        )
        self.assertEqual(
            batch_mock.call_args_list[1][0][0],
            [
                ("10000003", False, "test_user_4", "4"),
            ],
        )

    @patch("management.management.commands.utils.BOOT_STRAP_SERVICE")
    def test_process_batch(self, mock_bss):
        username = "test_user"
        user_id = "u1"
        org_id = "o1"
        is_admin = True
        batch = [("o1", True, "test_user", "u1")]
        process_batch(batch)
        user = mock_bss.import_bulk_users.call_args[0][0][0]
        self.assertEqual(user.username, username)
        self.assertEqual(user.user_id, user_id)
        self.assertEqual(user.org_id, org_id)
        self.assertEqual(user.admin, is_admin)

    @patch("management.management.commands.utils.BOOT_STRAP_SERVICE")
    def test_retrying_bulk(self, mock_bss):
        mock_bss.import_bulk_users.side_effect = [
            IntegrityError("IntegrityError: duplicate key value violates unique constraint"),
            None,
        ]

        batch = [("o1", True, "test_user", "u1")]
        process_batch(batch)
        self.assertEqual(mock_bss.import_bulk_users.call_count, 2)

    def test_import_service_account_data(self):
        client_id_1 = "8c22358-c2ab-40cc-bbc1-e4eff3exxb37xx"
        client_id_2 = "1421687f3-2bc0-4128-9d52-b92b9a22a631"
        user_id_1 = "b6333341-f028-4f29-852e-375132644bcc"
        user_id_2 = "181sdf16-414d-48dd-80a1-264df5d4ffd1"
        id_mapping = {client_id_1: user_id_1, client_id_2: user_id_2}
        tenant_1 = Tenant.objects.create(tenant_name="test_tenant_1")
        tenant_2 = Tenant.objects.create(tenant_name="test_tenant_2")
        mock_file_content = f"""user_id,client_id
{user_id_1},{client_id_1}
133331a4-10f3-4e84-83de-48b91f8faxx9,1b49xxc18-9915-40e2-972a-c8759632ac59
a210f23c-f2d2-40c6-b47c-43fa1bgg814a,0dffe7e11-c56e-4fcb-b7a6-66db2e013983
212cdcfe-e332-445c-bc35-4cc0xx8391d2,164x0f206-1161-446c-8bfd-b05039feec71
{user_id_2},{client_id_2}
"""
        principals = Principal.objects.bulk_create(
            [
                Principal(
                    username=SERVICE_ACCOUNT_USERNAME_FORMAT.format(clientId=client_id_1),
                    service_account_id=client_id_1,
                    type=Principal.Types.SERVICE_ACCOUNT,
                    tenant=tenant_1,
                ),
                Principal(
                    username=SERVICE_ACCOUNT_USERNAME_FORMAT.format(clientId=client_id_2),
                    service_account_id=client_id_2,
                    user_id="wrong_user_id",
                    type=Principal.Types.SERVICE_ACCOUNT,
                    tenant=tenant_2,
                ),
            ]
        )
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            populate_service_account_data("file_name")

        for principal in principals:
            principal.refresh_from_db()
            self.assertEqual(id_mapping[principal.service_account_id], principal.user_id)
