from django.contrib import admin
from .models import (
    ActionNotification,
    Appointment,
    Area,
    AreaRelatedRisk,
    CollectiveProtection,
    Confirmation,
    ConfirmationEvent,
    Contribution,
    ContractorOrg,
    DailyOpenClose,
    Equipment,
    InfoNotification,
    Permit,
    PermitStatus,
    PersonalProtection,
    Role,
    SafetyMeasure,
    User,
    WorkerTeam,
)

# Register your models here.
class AreaAdmin(admin.ModelAdmin):
    list_display = ("id", "name")
    filter_horizontal = ["associated_risks", "required_personal_protection"]

class AreaRelatedRiskAdmin(admin.ModelAdmin):
    list_display = ("id", "name")

class CollectiveProtectionAdmin(admin.ModelAdmin):
    list_display = ("id", "name")

class ContractorOrgAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "number")

class EquipmentAdmin(admin.ModelAdmin):
    list_display = ("id", "tag", "area")

class PermitAdmin(admin.ModelAdmin):
    list_display = ("id", "created_on", "tech_completion_time")

class PermitStatusAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "short_description")

class PersonalProtectionAdmin(admin.ModelAdmin):
    list_display = ("id", "name")

class RoleAdmin(admin.ModelAdmin):
    list_display = ("id", "name")

class SafetyMeasureAdmin(admin.ModelAdmin):
    list_display = ("id", "name")

class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "username", "email", "org")
    filter_horizontal = ["eligible_for_roles"]

admin.site.register(ActionNotification)
admin.site.register(Appointment)
admin.site.register(Area, AreaAdmin)
admin.site.register(AreaRelatedRisk, AreaRelatedRiskAdmin)
admin.site.register(CollectiveProtection, CollectiveProtectionAdmin)
admin.site.register(Confirmation)
admin.site.register(ConfirmationEvent)
admin.site.register(Contribution)
admin.site.register(ContractorOrg, ContractorOrgAdmin)
admin.site.register(DailyOpenClose)
admin.site.register(Equipment, EquipmentAdmin)
admin.site.register(InfoNotification)
admin.site.register(Permit, PermitAdmin)
admin.site.register(PermitStatus, PermitStatusAdmin)
admin.site.register(PersonalProtection, PersonalProtectionAdmin)
admin.site.register(Role, RoleAdmin)
admin.site.register(SafetyMeasure, SafetyMeasureAdmin)
admin.site.register(User, UserAdmin)
admin.site.register(WorkerTeam)
