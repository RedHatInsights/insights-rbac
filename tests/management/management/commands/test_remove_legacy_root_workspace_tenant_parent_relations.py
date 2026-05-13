"""Tests for remove_legacy_root_workspace_tenant_parent_relations management command."""

#
# Copyright 2026 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
from io import StringIO
from unittest.mock import patch

from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings


class RemoveLegacyRootWorkspaceTenantParentRelationsCommandTests(TestCase):
    """Tests for remove_legacy_root_workspace_tenant_parent_relations."""

    def test_requires_all(self):
        with self.assertRaises(CommandError):
            call_command("remove_legacy_root_workspace_tenant_parent_relations")

    @override_settings(REPLICATION_TO_RELATION_ENABLED=False)
    def test_skipped_writes_reason_to_stdout(self):
        out = StringIO()
        call_command(
            "remove_legacy_root_workspace_tenant_parent_relations",
            "--all",
            stdout=out,
        )
        self.assertIn("REPLICATION_TO_RELATION_ENABLED", out.getvalue())

    @patch(
        "management.management.commands.remove_legacy_root_workspace_tenant_parent_relations."
        "remove_legacy_root_workspace_tenant_parent_relations"
    )
    def test_all_invokes_util(self, mock_remove):
        mock_remove.return_value = {
            "skipped": False,
            "tenants_processed": 2,
        }
        out = StringIO()
        call_command("remove_legacy_root_workspace_tenant_parent_relations", "--all", stdout=out)
        mock_remove.assert_called_once_with()
        self.assertIn("tenants_processed=2", out.getvalue())
