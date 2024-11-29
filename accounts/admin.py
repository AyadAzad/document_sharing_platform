from django.contrib.auth.admin import UserAdmin
from django.contrib import admin
from .models import Documents, CustomUser, FileTransfer, UserKeys



# Register your models here.
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'first_name', 'role', 'last_name', 'is_active', 'is_staff')
    list_filter = ('role', 'is_active', 'is_staff')
    ordering = ('email',)
    search_fields = ('email', 'first_name', 'last_name')

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'role', 'public_key')}),
        ('Permissions', {'fields': ('is_active', 'is_staff')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'role', 'password1', 'password2', 'public_key'),
        }),
    )
    filter_horizontal = ()


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Documents)
admin.site.register(FileTransfer)
admin.site.register(UserKeys)
