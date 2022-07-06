from rest_framework import serializers


class UserSerializer(serializers.BaseSerializer):
    def to_representation(self, instance):
        ret = dict()
        ret['ldapAdmin'] = instance.ldap_admin
        ret['entryUUID'] = instance.entry_uuid
        ret['hasSubordinates']: 'FALSE'
        ret['objectClass'] = [
            'top',
            'posixAccount',
            'shadowAccount',
            'organizationalPerson',
            'inetOrgPerson',
            'person'
        ]
        ret['cn'] = instance.username
        ret['uidNumber'] = instance.uid_number
        ret['userPassword'] = instance.ldap_password
        ret['gidNumber'] = instance.primary_group.gid_number
        ret['uid'] = instance.username
        ret['displayName'] = ('%s %s' % (instance.first_name, instance.last_name)).strip()
        ret['givenName'] = instance.first_name
        ret['sn'] = instance.last_name
        ret['mail'] = instance.email
        ret['homeDirectory'] = '/home/%s' % instance.username
        ret['loginShell'] = '/bin/bash'
        ret['memberOf'] = instance.groups.values_list('name', flat=True)

        return ret


class GroupSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        ret = dict()
        ret['entryUUID'] = instance.entry_uuid
        ret['hasSubordinates']: 'FALSE'
        ret['objectClass'] = [
            'top',
            'posixGroup'
        ]
        ret['cn'] = instance.name
        ret['gidNumber'] = instance.gid_number
        ret['description'] = instance.description
        ret['ou'] = [instance.ou.name]
        ret['memberUid'] = instance.user_set.values_list('username', flat=True)

        return ret
