from django.db import models
from django.contrib.auth.models import AbstractUser, Group as ContribGroup
from django.utils.translation import gettext_lazy as _
from .validators import LowercaseASCIIUsernameValidator, LowercaseASCIIGroupnameValidator
from .utils import gen_ssha_hash, gen_entry_uuid


class User(AbstractUser):
    username_validator = LowercaseASCIIUsernameValidator()

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Lowercase English letters, digits and -/_ only.'),
        validators=[username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
    ldap_password = models.CharField(max_length=128, unique=False, verbose_name='LDAP password')
    entry_uuid = models.CharField(max_length=128, unique=True, blank=False, null=False)
    uid_number = models.PositiveIntegerField(unique=True, blank=False, null=False, verbose_name='UID number')
    primary_group = models.ForeignKey('ldap.Group', blank=False, null=False, on_delete=models.RESTRICT, related_name='user_primary_group', verbose_name='Primary LDAP group')
    ldap_admin = models.BooleanField(default=False, verbose_name='LDAP Administrator')

    def set_password(self, raw_password):
        super().set_password(raw_password)
        self.ldap_password = gen_ssha_hash(raw_password)

    def save(self, *args, **kwargs):
        if len(self.entry_uuid) == 0:
            self.entry_uuid = gen_entry_uuid(self.username)
        return super().save(*args, **kwargs)


class Group(ContribGroup):
    ldap_name_validator = LowercaseASCIIGroupnameValidator()

    ldap_name = models.CharField(
        _('name'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Lowercase English letters, digits and -/_ only.'),
        validators=[ldap_name_validator],
        error_messages={
            'unique': _("A group with that name already exists."),
        },
    )
    entry_uuid = models.CharField(max_length=128, unique=True, blank=False, null=False)
    gid_number = models.PositiveIntegerField(unique=True, blank=False, null=False, verbose_name='GID number')
    description = models.CharField(max_length=128, unique=False, blank=True, null=True)

    def save(self, *args, **kwargs):
        self.name = self.ldap_name

        if len(self.entry_uuid) == 0:
            self.entry_uuid = gen_entry_uuid(self.ldap_name)
        return super().save(*args, **kwargs)
