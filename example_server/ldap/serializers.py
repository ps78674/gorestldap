from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.core.validators import EmailValidator
from .models import User, Group
from .validators import LowercaseASCIIUsernameValidator, LowercaseASCIIGroupnameValidator


class StrictReadOnlyFieldsMixin:
    default_error_messages = {
        'read_only': _('This field is read only')
    }

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if not hasattr(self, 'initial_data'):
            return attrs

        read_only_fields = { field_name for field_name, field in self.fields.items() if field.read_only } | set(getattr(self.Meta, 'read_only_fields', set()))
        received_read_only_fields = set(self.initial_data) & read_only_fields
        if received_read_only_fields:
            errors = {}
            for field_name in received_read_only_fields:
                errors[field_name] = serializers.ErrorDetail(self.error_messages['read_only'], code='read_only')

            raise serializers.ValidationError(errors)

        return attrs


class UserSerializer(StrictReadOnlyFieldsMixin, serializers.ModelSerializer):
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
    mail = serializers.CharField(source='email', required=False, validators=[EmailValidator()])
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
