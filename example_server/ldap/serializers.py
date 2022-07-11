from rest_framework import serializers
from .models import User, Group


class UserSerializer(serializers.ModelSerializer):
    ldapAdmin = serializers.BooleanField(source='ldap_admin')
    entryUUID = serializers.CharField(source='entry_uuid')
    hasSubordinates = serializers.SerializerMethodField()
    objectClass = serializers.SerializerMethodField()
    cn = serializers.CharField(source='username')
    uidNumber = serializers.IntegerField(source='uid_number')
    userPassword = serializers.CharField(source='ldap_password')
    gidNumber = serializers.SlugRelatedField(source='primary_group', slug_field='gid_number', queryset=Group.objects.all())
    uid = serializers.CharField(source='username')
    displayName = serializers.SerializerMethodField()
    givenName = serializers.CharField(source='first_name')
    sn = serializers.CharField(source='last_name')
    mail = serializers.CharField(source='email')
    homeDirectory = serializers.SerializerMethodField()
    loginShell = serializers.SerializerMethodField()
    memberOf = serializers.SlugRelatedField(source='groups', slug_field='name', queryset=Group.objects.all(), many=True)

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
    entryUUID = serializers.CharField(source='entry_uuid')
    hasSubordinates = serializers.SerializerMethodField()
    objectClass = serializers.SerializerMethodField()
    cn = serializers.CharField(source='name')
    gidNumber = serializers.IntegerField(source='gid_number')
    description = serializers.CharField()
    memberUid = serializers.SlugRelatedField(source='user_set', slug_field='username', queryset=User.objects.all(), many=True)

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
