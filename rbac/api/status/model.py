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

"""Models to capture server status."""

import os
import subprocess

from api import API_VERSION


class Status:
    """A server's status."""

    @property
    def commit(self):  # pylint: disable=R0201
        """Collect the build number for the server.

        :returns: A build number
        """
        commit_info = os.environ.get("OPENSHIFT_BUILD_COMMIT", None)
        if commit_info is None:
            commit_info = subprocess.run(["git", "describe", "--always"], stdout=subprocess.PIPE)
            if commit_info.stdout:
                commit_info = commit_info.stdout.decode("utf-8").strip()
        return commit_info

    @property
    def api_version(self):
        """Return the API version."""
        return API_VERSION
