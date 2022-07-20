from rest_framework import serializers
from .models import User, Group
from .validators import LowercaseASCIIUsernameValidator, LowercaseASCIIGroupnameValidator


class UserSerializer(serializers.ModelSerializer):
    ldapAdmin = serializers.BooleanField(source='ldap_admin', required=False)
    entryUUID = serializers.CharField(source='entry_uuid', required=False)
    hasSubordinates = serializers.SerializerMethodField()
    objectClass = serializers.SerializerMethodField()
    cn = serializers.CharField(source='username', validators=[LowercaseASCIIUsernameValidator()], required=False)
    uidNumber = serializers.IntegerField(source='uid_number', required=False)
    userPassword = serializers.CharField(source='ldap_password', required=False)
    gidNumber = serializers.SlugRelatedField(source='primary_group', slug_field='gid_number', queryset=Group.objects.all(), required=False)
    uid = serializers.CharField(source='username', read_only=True)
    displayName = serializers.SerializerMethodField()
    givenName = serializers.CharField(source='first_name', required=False)
    sn = serializers.CharField(source='last_name', required=False)
    mail = serializers.CharField(source='email', required=False)
    homeDirectory = serializers.SerializerMethodField()
    loginShell = serializers.SerializerMethodField()
    memberOf = serializers.SlugRelatedField(source='groups', slug_field='name', queryset=Group.objects.all(), many=True, required=False)

    class Meta:
        model = User
        fields = [
            'ldapAdmin',
            'entryUUID',
            'hasSubordinates',
            'objectClass',
            'cn',
            'uidNumber',
            'userPassword',
            'gidNumber',
            'uid',
            'displayName',
            'givenName',
            'sn',
            'mail',
            'homeDirectory',
            'loginShell',
            'memberOf'
        ]

    def get_hasSubordinates(self, obj):
        return 'FALSE'

    def get_objectClass(self, obj):
        object_classes = [
            'top',
            'posixAccount',
            'shadowAccount',
            'organizationalPerson',
            'inetOrgPerson',
            'person'
        ]
        return object_classes

    def get_displayName(self, obj):
        return ('%s %s' % (obj.first_name, obj.last_name)).strip()

    def get_homeDirectory(self, obj):
        return '/home/%s' % obj.username

    def get_loginShell(self, obj):
        return '/bin/bash'


class GroupSerializer(serializers.ModelSerializer):
    entryUUID = serializers.CharField(source='entry_uuid', required=False)
    hasSubordinates = serializers.SerializerMethodField()
    objectClass = serializers.SerializerMethodField()
    cn = serializers.CharField(source='ldap_name', validators=[LowercaseASCIIGroupnameValidator()], required=False)
    gidNumber = serializers.IntegerField(source='gid_number', required=False)
    description = serializers.CharField(required=False)
    memberUid = serializers.SlugRelatedField(source='user_set', slug_field='username', queryset=User.objects.all(), many=True, required=False)

    class Meta:
        model = User
        fields = [
            'entryUUID',
            'hasSubordinates',
            'objectClass',
            'cn',
            'gidNumber',
            'description',
            'memberUid'
        ]

    def get_hasSubordinates(self, obj):
        return 'FALSE'

    def get_objectClass(self, obj):
        object_classes = [
            'top',
            'posixGroup'
        ]
        return object_classes
