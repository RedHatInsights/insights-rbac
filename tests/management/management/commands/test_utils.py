
from io import StringIO
from unittest.mock import mock_open, patch

from django.db.utils import IntegrityError
from django.test import TestCase

from management.management.commands.utils import populate_tenant_user_data, process_batch


class TestProcessBatch(TestCase):

    @patch("management.management.commands.utils.process_batch")
    def test_populate_tenant_user_data(self, batch_mock):
        mock_file_content = "orgs_info[0].id,orgs_info[0].perm[0],principals[0],_id\n1000000,admin:org:all,test_user_1,1\n10000001,admin:org:all,test_user_2,2\n"
                                     
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            populate_tenant_user_data(start_line=2)

        batch_mock.assert_called_once_with(
            [
                ("10000001", True, "test_user_2", "2"),
            ]
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
