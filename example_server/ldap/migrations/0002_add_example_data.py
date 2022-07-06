from django.db import migrations
from django.contrib.auth.hashers import make_password
from rest_framework.authtoken.models import Token

from ..models import OU, Group, User
from ..utils import gen_ssha_hash


OU_NAME = 'ou'

USER_DATA = {
    'name': 'admin',
    'password': 'admin',
    'uid_number': 1000,
    'first_name': 'Ivan',
    'last_name': 'Petrov',
    'email': 'i.petrov@example.com'
}

PRIMARY_GROUP_DATA = {
    'name': 'primary_group',
    'gid_number': 1999
}

GROUPS_DATA = [
    {
        'name': 'group_a',
        'gid_number': 2000
    },
    {
        'name': 'group_b',
        'gid_number': 2001
    }
]


def fill_data(*args, **kwargs):
    ou = OU.objects.create(name=OU_NAME)

    pgroup = Group.objects.create(
        name = PRIMARY_GROUP_DATA['name'],
        gid_number = PRIMARY_GROUP_DATA['gid_number'],
        ou = ou
    )

    pw = make_password(USER_DATA['password'])
    lpw = gen_ssha_hash(USER_DATA['password'])
    user = User.objects.create(
        username = USER_DATA['name'],
        password = pw,
        ldap_password = lpw,
        uid_number = USER_DATA['uid_number'],
        primary_group = pgroup,
        ldap_admin=True,
        first_name = USER_DATA['first_name'],
        last_name = USER_DATA['last_name'],
        email = USER_DATA['email'],
        is_superuser = True,
        is_staff = True
    )

    user.groups.add(pgroup)

    for g in GROUPS_DATA:
        group = Group.objects.create(
            name = g['name'],
            gid_number = g['gid_number'],
            ou = ou
        )

        user.groups.add(group)

    token = Token.objects.create(user=user)
    print('\n\n\tCreated new auth token %s\n' % token)


class Migration(migrations.Migration):
    dependencies = [
        ('ldap', '0001_initial')
    ]

    operations = [
        migrations.RunPython(fill_data)
    ]
