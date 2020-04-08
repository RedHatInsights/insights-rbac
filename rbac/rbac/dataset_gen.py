import base64
import json
import random
import time
import uuid

from django.db import transaction
from django.urls import reverse
import requests
from tenant_schemas.utils import schema_context

from api.models import Tenant
from api.serializers import create_schema_name
from management.models import Principal, Group, Policy, Role, Access, ResourceDefinition

ACCOUNT_ID = 10001
HEADER = 'x-rh-identity'
ADMIN_HEADER_RAW = dict(
    identity=dict(
        account_number=ACCOUNT_ID,
        type='User',
        user=dict(
            username='admin',
            email='admin@example.com',
            is_org_admin=True
        )
    )
)
ADMIN_HEADER = base64.b64encode(json.dumps(ADMIN_HEADER_RAW).encode('utf8'))
URL_BASE = 'http://localhost:8000'

def generate_dataset(principals=1, groups=1, policies=1, roles=1):
    generated_data = dict()
    session = requests.Session()
    session.headers[HEADER] = ADMIN_HEADER

    with transaction.atomic():
        tenant, _ = Tenant.objects.get_or_create(schema_name=create_schema_name(ACCOUNT_ID))
        with schema_context(create_schema_name(ACCOUNT_ID)):
            generated_data['principals'] = dict()
            for i in range(principals):
                p = Principal.objects.create(
                    uuid=uuid.uuid4(),
                    username=f'user-{i}'
                )
                generated_data['principals'][p.uuid] = dict(username=f'user-{i}')
    
    
    generated_data['groups'] = dict()
    for i in range(groups):
        group_url = reverse('group-list')
        response = session.post(
            f'{URL_BASE}{group_url}',
            json=dict(name=f'group-{i}', description=f'Group {i}')
        )
        print(response.content)
        response.raise_for_status()
        generated_data['groups'][response.json()['uuid']] = dict()
    
    for principal_uuid in generated_data['principals'].keys():
        group_uuid = random.choice(list(generated_data['groups'].keys()))
        group_principals_url = reverse('group-principals', args=(group_uuid,))
        response = session.post(
            f'{URL_BASE}{group_principals_url}',
            json=dict(
                principals=[
                    dict(username=generated_data['principals'][principal_uuid]['username'])
                ]
            )
        )
        print(response.content)
        response.raise_for_status()
        generated_data['principals'][principal_uuid].setdefault('groups', []).append(group_uuid)
        generated_data['groups'][group_uuid].setdefault('principals', []).append(principal_uuid)
    
    generated_data['roles'] = dict()
    for i in range(roles):
        role_url = reverse('role-list')
        response = session.post(
            f'{URL_BASE}{role_url}',
            json=dict(
                name=f'role-{i}',
                description=f'Role {i}',
                access=[
                    dict(permission='foo:bar:baz', resourceDefinitions=[])
                ]
            )
        )
        print(response.content)
        response.raise_for_status()
        generated_data['roles'][response.json()['uuid']] = dict()
    
    for i in range(policies):
        policy_url = reverse('policy-list')
        group_uuid = random.choice(list(generated_data['groups'].keys()))
        role_uuid = random.choice(list(generated_data['roles'].keys()))
        response = session.post(
            f'{URL_BASE}{policy_url}',
            json=dict(
                name=f'policy-{i}',
                description=f'Policy {i}',
                group=group_uuid,
                roles=[role_uuid]
            )
        )
        print(response.content)
        response.raise_for_status()
        generated_data['roles'][role_uuid].setdefault('groups', []).append(group_uuid)
        generated_data['groups'][group_uuid].setdefault('roles', []).append(role_uuid)
    return generated_data

def stresstest(n=1000):
    tenant, _ = Tenant.objects.get_or_create(schema_name=create_schema_name(ACCOUNT_ID))
    with schema_context(create_schema_name(ACCOUNT_ID)):
        principals = list(Principal.objects.exclude(username='user_dev'))
    time_series = []
    access_url = reverse('access')
    for i in range(n):
        principal = random.choice(principals)
        start_time = time.time()
        response = requests.get(
            f'{URL_BASE}{access_url}',
            params=dict(application='foo', username=principal.username),
            headers={HEADER: ADMIN_HEADER}
        )
        print(response.content)
        response.raise_for_status()
        end_time = time.time()
        time_series.append(end_time-start_time)
    total_time = sum(time_series) * 1000
    avg_time = total_time / len(time_series)
    min_time = min(time_series) * 1000
    max_time = max(time_series) * 1000
    print('Total time: %.4fms; Avg: %.4fms; Min: %.4fms; Max: %.4fms' % (total_time, avg_time, min_time, max_time))
 
