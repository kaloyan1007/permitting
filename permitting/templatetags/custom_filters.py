from django import template
from django.template.defaultfilters import stringfilter

register = template.Library()

@register.filter
def count_active_notifs(notifs):
    return notifs.filter(is_active=True).count()


@register.filter
@stringfilter
def model_field_names_to_proper(value):
    mapping = {
        "name": "Name",
        "number": "Number",
        "eligible_for_roles": "Eligible For Roles",
        "org": "Organization",
        "groups": "Groups",
        "user_permissions": "User Permissions",
        "description": "Description",
        "associated_risks": "Associated Risks",
        "required_personal_protection": "Required Personal Protection",
        "tag": "Tag",
        "area": "Area",
        "short_description": "Short Description",
        "collective_protection": "Collective Protection",
        "created_on": "Created On",
        "personal_protection": "Personal Protection",
        "risks": "Risks",
        "safety_measures": "Safety Measures",
        "status": "Status",
        "targeted_equipment": "Targeted Equipment",
        "task_description": "Task Description",
        "tech_completion_time": "Tech Completion Time",
        "tests_and_golive_comment": "Tests And Go-live Comment",
        "permit": "Permit",
        "person": "Person",
        "role": "Role",
        "date_joined": "Joined",
        "date_left": "Left",
        "debriefed_general": "Received General Debriefing",
        "debriefed_specifics": "Received Specifics Debriefing",
        "worker": "Worker",
        "closed_at": "Closed At",
        "confirmed_led_workers_in": "Confirmed Led Workers In",
        "confirmed_led_workers_out": "Confirmed Led Workers Out",
        "confirmed_loto_in_place": "Confirmed LOTO In Place",
        "opened_at": "Opened At",
        "confirmed": "Confirmed",
        "what": "What",
        "author": "Author",
        "comment": "Comment",

        "issuer": "Issuer",
        "task_responsible": "Task Responsible",
        "authorizer": "Authorizer",
        "foreman": "Foreman",
        "loto_officer": "LOTO Officer",
        "safety_gatekeeper": "Safety Gatekeeper",

        "initialization_ok": "Initialization OK",
        "loto_in_place": "LOTO In Place",
        "performed_general_safety_briefing": "Performed General Safety Briefing",
        "performed_task_specific_briefing": "Performed Task Specific Briefing",
        "task_completed": "Task Completed",
        "workplace_cleaned": "Workplace Cleaned",
        "eq_safe_to_operate": "Equipment Safe To Operate",
        "allowed_loto_removal": "Allowed LOTO Removal",
        "loto_removed": "LOTO Removed",
    }

    return mapping.get(value, value)
