from django.contrib import admin
from django.contrib.auth.models import Group as ContribGroup
from django.contrib.auth.admin import UserAdmin as ContribUserAdmin, GroupAdmin as ContribGroupAdmin
from django.utils.translation import gettext_lazy as _
from .models import User, Group, OU


@admin.register(OU)
class OUAdmin(admin.ModelAdmin):
    pass


class UserAdmin(ContribUserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password', 'uid_number', 'primary_group', 'ldap_admin')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'uid_number', 'primary_group'),
        }),
    )

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        form.instance.groups.add(form.instance.primary_group)
    

class GroupAdmin(ContribGroupAdmin):
    fieldsets = (
        (None, {'fields': ('name', 'gid_number', 'ou', 'permissions')}),
    )


admin.site.unregister(ContribGroup)
admin.site.register(User, UserAdmin)
admin.site.register(Group, GroupAdmin)
