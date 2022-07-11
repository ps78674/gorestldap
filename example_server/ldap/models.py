from django.db import models
from django.contrib.auth.models import AbstractUser, Group as ContribGroup
from .utils import gen_ssha_hash, gen_entry_uuid


class User(AbstractUser):
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
    entry_uuid = models.CharField(max_length=128, unique=True, blank=False, null=False)
    gid_number = models.PositiveIntegerField(unique=True, blank=False, null=False, verbose_name='GID number')
    description = models.CharField(max_length=128, unique=False, blank=True, null=True)

    def save(self, *args, **kwargs):
        if len(self.entry_uuid) == 0:
            self.entry_uuid = gen_entry_uuid(self.name)
        return super().save(*args, **kwargs)
