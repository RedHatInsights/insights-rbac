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
from django.db import IntegrityError
from management.principal.model import Principal
from management.role.relation_api_dual_write_handler import OutboxReplicator
from management.tenant_mapping.model import logger
from management.tenant_service.v2 import V2TenantBootstrapService

from api.models import User


BOOT_STRAP_SERVICE = V2TenantBootstrapService(OutboxReplicator())


def get_file_path(file_name):
    """Get the file path for the users data."""
    return f"/tmp/{file_name}"


def get_s3_client():
    """Create and return an S3 client."""
    return boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("S3_AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("S3_AWS_SECRET_ACCESS_KEY"),
    )


def download_data_from_S3(file_name):
    """Download users data from S3."""
    s3_client = get_s3_client()
    file_path = get_file_path(file_name)

    if os.path.exists(file_path):
        os.remove(file_path)
        logger.info(f"Removed existing user data file: {file_path}")

    bucket = os.environ.get("S3_AWS_BUCKET")
    logger.info(f"Downloading file from S3 bucket: {bucket}")
    try:
        s3_client.download_file(f"{bucket}", f"users_data/{file_name}", file_path)
        logger.info("File downloaded successfully.")
    except ClientError as e:
        logger.info(f"Error downloading file: {e}")
        raise


def populate_tenant_user_data(file_name, start_line=1, batch_size=1000):
    """
    Populate tenant and user data from the downloaded file.

    Args:
        batch_size (int): Number of records to process in each batch.
        start(int): Line number to start processing from (1).
    """
    file_path = get_file_path(file_name)
    with open(file_path, "r") as file:
        csv_reader = csv.reader(file)
        # Skip lines until start
        for _ in range(start_line):
            next(csv_reader, None)
        batch_data = []
        for current_line, row in enumerate(csv_reader, start=start_line):
            org_id, admin, principal_name, user_id = row
            admin = admin == "admin:org:all"
            batch_data.append((org_id, admin, principal_name, user_id))
            if len(batch_data) >= batch_size:
                process_batch(batch_data)
                logger.info(f"Processed batch ending at line {current_line}")
                batch_data = []
        # Process any remaining records
        if batch_data:
            process_batch(batch_data)
            logger.info(f"Processed final batch ending at line {current_line}")
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
    try:
        BOOT_STRAP_SERVICE.import_bulk_users(users)
    except IntegrityError as e:
        """Retry once if there is creation conflict."""
        logger.info(f"IntegrityError: {e.__cause__}. Retrying import.")
        BOOT_STRAP_SERVICE.import_bulk_users(users)


def populate_service_account_data(file_name):
    """Populate service account data from the downloaded file."""
    file_path = get_file_path(file_name)
    id_mapping = {}
    with open(file_path, "r") as file:
        csv_reader = csv.reader(file)
        next(csv_reader, None)  # Skip header
        for row in csv_reader:
            user_id, client_id = row
            id_mapping[client_id] = user_id
    for principal in Principal.objects.filter(type=Principal.Types.SERVICE_ACCOUNT):
        principal.user_id = id_mapping.get(principal.service_account_id)
        principal.save()
