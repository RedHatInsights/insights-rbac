#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Functions for importing users data."""
import csv
import os

import boto3
from botocore.exceptions import ClientError
from management.role.relation_api_dual_write_handler import OutboxReplicator
from management.tenant_service.v2 import V2TenantBootstrapService

from api.models import User


FILE_NAME = "data_user.csv"
FILE_PATH = f"/tmp/{FILE_NAME}"
BOOT_STRAP_SERVICE = V2TenantBootstrapService(OutboxReplicator())


def get_s3_client():
    """Create and return an S3 client."""
    return boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("S3_AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("S3_AWS_SECRET_ACCESS_KEY"),
    )


def download_tenant_user_data():
    """Download users data from S3."""
    s3_client = get_s3_client()
    if os.path.exists(FILE_PATH):
        os.remove(FILE_PATH)
        print(f"Removed existing user data file: {FILE_PATH}")

    bucket = os.environ.get("S3_AWS_BUCKET")
    print(f"Downloading file from S3 bucket: {bucket}")
    try:
        s3_client.download_file(f"{bucket}", f"users_data/{FILE_NAME}", FILE_PATH)
        print("File downloaded successfully.")
    except ClientError as e:
        print(f"Error downloading file: {e}")
        raise


def populate_tenant_user_data(start_line=1, batch_size=1000):
    """
    Populate tenant and user data from the downloaded file.

    Args:
        batch_size (int): Number of records to process in each batch.
        start(int): Line number to start processing from (1).
    """
    with open(FILE_PATH, "r") as file:
        csv_reader = csv.reader(file)
        # Skip lines until start
        for _ in range(start_line - 1):
            next(csv_reader, None)
        batch_data = []
        for current_line, row in enumerate(csv_reader, start=start_line):
            org_id, admin, principal_name, user_id = row
            batch_data.append((org_id, admin, principal_name, user_id))
            if len(batch_data) >= batch_size:
                process_batch(batch_data)
                print(f"Processed batch ending at line {current_line}")
                batch_data = []
        # Process any remaining records
        if batch_data:
            process_batch(batch_data)
            print(f"Processed final batch ending at line {current_line}")
    return


def process_batch(batch_data):
    """Process a batch of tenant and principal data."""
    users = []
    for org_id, org_admin, principal_name, user_id in batch_data:
        user = User()
        user.org_id = org_id
        user.admin = org_admin
        user.username = principal_name
        user.user_id = user_id
        user.is_active = True
        users.append(user)

    BOOT_STRAP_SERVICE.update_users(users)
