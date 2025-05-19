from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

# To implement 'User' concept
class ContractorOrg(models.Model):
    name = models.CharField(max_length=255)
    number = models.IntegerField()

    def __str__(self):
        return f"{self.name} ({self.number})"

class Role(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class User(AbstractUser):
    eligible_for_roles = models.ManyToManyField(Role, blank=True, related_name="eligible")
    org = models.ForeignKey(ContractorOrg, blank=True, null=True, on_delete=models.SET_NULL, related_name="employees")
    # Just to resolve errors with `makemigrations`:
    groups = models.ManyToManyField(Group, blank=True, related_name="custom_user_set")
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name="custom_user_permissions")

# To implement 'Area' concept
class AreaRelatedRisk(models.Model):
    description = models.TextField()
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class PersonalProtection(models.Model):
    description = models.TextField(blank=True)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Area(models.Model):
    associated_risks = models.ManyToManyField(AreaRelatedRisk, related_name="inherent_for_areas")
    name = models.CharField(max_length=255)
    required_personal_protection = models.ManyToManyField(PersonalProtection, related_name="required_in_areas")

    def __str__(self):
        return self.name

# To implement 'Permit' concept
class CollectiveProtection(models.Model):
    description = models.TextField()
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Equipment(models.Model):
    description = models.TextField()
    tag = models.CharField(max_length=255)
    area = models.ForeignKey(Area, null=True, on_delete=models.SET_NULL, related_name="equipments")

    def __str__(self):
        return self.tag

class SafetyMeasure(models.Model):
    description = models.TextField()
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class PermitStatus(models.Model):
    short_description = models.CharField(max_length=255)
    name = models.CharField(max_length=4)

    def __str__(self):
        return f"{self.name} ({self.short_description})"

    class Meta:
        verbose_name = 'PermitStatus'
        verbose_name_plural = 'PermitStatuses'

class Permit(models.Model):
    collective_protection = models.ManyToManyField(CollectiveProtection, blank=True, related_name="assigned_in_permits")
    created_on = models.DateTimeField(auto_now_add=True)
    personal_protection = models.ManyToManyField(PersonalProtection, blank=True, related_name="assigned_in_permits")
    risks = models.ManyToManyField(AreaRelatedRisk, blank=True, related_name="considered_in_permits")
    safety_measures = models.ManyToManyField(SafetyMeasure, blank=True, related_name="assigned_in_permits")
    status = models.ForeignKey(PermitStatus, null=True, on_delete=models.SET_NULL, related_name="permits")
    targeted_equipment = models.ManyToManyField(Equipment, related_name="permits")
    task_description = models.TextField()
    tech_completion_time = models.DateTimeField(null=True, blank=True)
    tests_and_golive_comment = models.TextField()

    def __str__(self):
        return f"permit {self.id}, status: {self.status.short_description}"

class Appointment(models.Model):
    permit = models.ForeignKey(Permit, on_delete=models.CASCADE, related_name="appointments")
    person = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="appointed_to")
    role = models.ForeignKey(Role, null=True, on_delete=models.SET_NULL, related_name="appointments")

class WorkerTeam(models.Model):
    date_joined = models.DateTimeField(auto_now_add=True)
    date_left = models.DateTimeField(null=True, blank=True)
    debriefed_general = models.BooleanField(default=False)
    debriefed_specifics = models.BooleanField(default=False)
    permit = models.ForeignKey(Permit, on_delete=models.CASCADE)
    worker = models.ForeignKey(User, on_delete=models.CASCADE, related_name="in_workers_team")

class DailyOpenClose(models.Model):
    closed_at = models.DateTimeField(null=True, blank=True)
    confirmed_led_workers_in = models.BooleanField(default=False)
    confirmed_led_workers_out = models.BooleanField(default=False)
    confirmed_loto_in_place = models.BooleanField(default=False)
    opened_at = models.DateTimeField(null=True, blank=True)
    permit = models.ForeignKey(Permit, on_delete=models.CASCADE)

class ConfirmationEvent(models.Model):
    short_description = models.CharField(max_length=255)

    def __str__(self):
        return self.short_description

class Confirmation(models.Model):
    confirmed = models.BooleanField(null=True, blank=True)
    permit = models.ForeignKey(Permit, on_delete=models.CASCADE, related_name="confirmations")
    what = models.ForeignKey(ConfirmationEvent, on_delete=models.CASCADE)

class Contribution(models.Model):
    author = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="authored_contributions")
    comment = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True)
    permit = models.ForeignKey(Permit, on_delete=models.CASCADE, related_name="contributions")
    permit_total_content = models.JSONField()

# To implement 'Notification' concept
class Notification(models.Model):
    created_on = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(null=True, blank=True)
    is_read = models.BooleanField(null=True, blank=True)
    message = models.TextField()
    permit = models.ForeignKey(Permit, on_delete=models.CASCADE)
    target_viewname = models.TextField()
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)

    class Meta:
        abstract = True

class ActionNotification(Notification):
    created_at_status = models.ForeignKey(PermitStatus, null=True, on_delete=models.SET_NULL)
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="action_notifications")

class InfoNotification(Notification):
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="info_notifications")
