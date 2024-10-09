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
from django.db import transaction
from django.db.models import Q
from management.principal.model import Principal
from migration_tool.migrate import migrate_workspace, relationships_for_new_user

from api.models import Tenant


# The file is put under users-data/<env>/data.user.csv
BUCKET_NAME = "users-data"
FILE_NAME = "data.user.csv"
FILE_PATH = f"/tmp/{FILE_NAME}"


def get_s3_client():
    """Create and return an S3 client."""
    return boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("S3_AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("S3_AWS_SECRET_ACCESS_KEY"),
    )


def download_tenant_user_data(env):
    """Download users data from S3."""
    s3_client = get_s3_client()
    if os.path.exists(FILE_PATH):
        os.remove(FILE_PATH)
        print(f"Removed existing user data file: {FILE_PATH}")

    print(f"Downloading file from S3 bucket: {BUCKET_NAME}/{env}")
    try:
        s3_client.download_file(BUCKET_NAME, env, FILE_PATH)
        print("File downloaded successfully.")
    except ClientError as e:
        print(f"Error downloading file: {e}")
        raise


def populate_tenant_user_data(start_line=1, batch_size=1000, env="stage"):
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
                process_batch(batch_data, env)
                print(f"Processed batch ending at line {current_line}")
                batch_data = []
        # Process any remaining records
        if batch_data:
            process_batch(batch_data, env)
            print(f"Processed final batch ending at line {current_line}")
    return

@transaction.atomic
def process_batch(batch_data, env):
    """Process a batch of tenant and principal data."""
    # Extract unique org_ids from the batch
    org_ids = set(item[0] for item in batch_data)

    # Fetch existing tenants
    existing_tenants = {tenant.org_id: tenant for tenant in Tenant.objects.filter(org_id__in=org_ids)}

    # Create new tenants
    new_tenants = [Tenant(tenant_name=f"org{org_id}", org_id=org_id) for org_id in org_ids if org_id not in existing_tenants]
    if new_tenants:
        tenants = Tenant.objects.bulk_create(new_tenants)
        # Update existing_tenants with newly created ones
        existing_tenants.update({tenant.org_id: tenant for tenant in tenants})

    for tenant in existing_tenants.values():
        migrate_workspace(tenant, True, env)

    # Prepare principal data
    principal_data = [
        (existing_tenants[org_id], org_admin, principal_name, user_id)
        for org_id, org_admin, principal_name, user_id in batch_data
    ]

    # Fetch existing principals
    existing_principals = Principal.objects.filter(
        Q(tenant__in=existing_tenants.values()) & Q(username__in=[item[1] for item in principal_data])
    )
    existing_principal_dict = {(p.tenant_id, p.username): p for p in existing_principals}

    new_principals= []
    principals_to_update = []

    for tenant, org_admin, principal_name, user_id in principal_data:
        key = (tenant.id, principal_name)
        if key in existing_principal_dict:
            principal = existing_principal_dict[key]
            if principal.user_id != user_id:
                principal.user_id = user_id
                principals_to_update.append(principal)
        else:
            new_principals.append(Principal(tenant=tenant, username=principal_name, user_id=user_id))
            relationships_for_new_user(user_id, org_admin, tenant)

    # Bulk update existing principals
    if principals_to_update:
        Principal.objects.bulk_update(principals_to_update, ["user_id"])
