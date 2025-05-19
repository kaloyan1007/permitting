from django.db import IntegrityError

from .models import (
    ActionNotification,
    Appointment,
    AreaRelatedRisk,
    CollectiveProtection,
    Confirmation,
    ConfirmationEvent,
    DailyOpenClose,
    Equipment,
    InfoNotification,
    PersonalProtection,
    Role,
    SafetyMeasure,
    WorkerTeam,
)


def appoint_for_duty(permit, role, person):
    # Check if there already is a person appointed for that position for the permit
    if Appointment.objects.filter(permit=permit, role=role).exists():
        raise IntegrityError

    # Make the appointment
    a = Appointment(
        permit=permit,
        person=person,
        role=role,
    )
    a.save()
    return


def check_all_from_input_in_permit_entry(
    input_list, resulting_many_to_many, test_instance
):
    temp = resulting_many_to_many.all()
    for i in range(0, temp.count()):
        test_instance.assertEqual(temp[i].id, int(input_list[i]))

    return

def deactivate_inapplicable_action_notifs(permit):
    active_action_notifs = ActionNotification.objects.filter(permit=permit, is_active=True).all()

    for notif in active_action_notifs:
        if notif.created_at_status != permit.status:
            notif.is_active = False
            notif.save()

    return

def get_full_permit_dict(permit):
    """
    Serializes a permit into a Python dict, so it can be later stored as JSON in the DB.
    In addition to the main Permit model, it also draws data from the Appointment, WorkerTeam, DailyOpenClose and GeneralConfirmation models.
    """
    a = Appointment.objects.filter(permit=permit)
    appointments = {}
    for item in a:
        appointments[f"{item.role.name}"] = item.person.username

    w = WorkerTeam.objects.filter(permit=permit)
    workers = [
        {
            "date_joined": (
                None
                if worker.date_joined is None
                else worker.date_joined.strftime("%Y/%m/%d %H:%M")
            ),
            "date_left": (
                None
                if worker.date_left is None
                else worker.date_left.strftime("%Y/%m/%d %H:%M")
            ),
            "debriefed_general": worker.debriefed_general,
            "debriefed_specifics": worker.debriefed_specifics,
            "worker": worker.worker.username,
        }
        for worker in w
    ]

    oc_logs = DailyOpenClose.objects.filter(permit=permit)
    daily_open_close = [
        {
            "closed_at": (
                None
                if log.closed_at is None
                else log.closed_at.strftime("%Y/%m/%d %H:%M")
            ),
            "confirmed_led_workers_in": log.confirmed_led_workers_in,
            "confirmed_led_workers_out": log.confirmed_led_workers_out,
            "confirmed_loto_in_place": log.confirmed_loto_in_place,
            "opened_at": (
                None
                if log.opened_at is None
                else log.opened_at.strftime("%Y/%m/%d %H:%M")
            ),
        }
        for log in oc_logs
    ]

    confirmations = {}

    for item in ConfirmationEvent.objects.all():
        gc = Confirmation.objects.filter(permit=permit, what=item)
        confirmations[f"{item.short_description}"] = (
            None if gc.count() < 1 else gc[0].confirmed
        )

    collective_protection = [
        item.name
        for item in CollectiveProtection.objects.filter(assigned_in_permits=permit)
    ]
    personal_protection = [
        item.name
        for item in PersonalProtection.objects.filter(assigned_in_permits=permit)
    ]
    risks = [
        item.name
        for item in AreaRelatedRisk.objects.filter(considered_in_permits=permit)
    ]
    safety_measures = [
        item.name for item in SafetyMeasure.objects.filter(assigned_in_permits=permit)
    ]
    targeted_equipment = [item.tag for item in Equipment.objects.filter(permits=permit)]

    full_permit = {
        "id": permit.id,
        "created_on": permit.created_on.strftime("%Y/%m/%d %H:%M"),
        "status": permit.status.name,
        "status_desc": permit.status.short_description,
        "task_description": permit.task_description,
        "collective_protection": collective_protection,
        "personal_protection": personal_protection,
        "risks": risks,
        "safety_measures": safety_measures,
        "targeted_equipment": targeted_equipment,
        "appointments": appointments,
        "workers": workers,
        "daily_open_close": daily_open_close,
        "confirmations": confirmations,
        "tech_completion_time": (
            None
            if permit.tech_completion_time is None
            else permit.tech_completion_time.strftime("%Y/%m/%d %H:%M")
        ),
        "tests_and_golive_comment": permit.tests_and_golive_comment,
    }

    return full_permit


def has_required_role(user, required_role_names):
    if isinstance(required_role_names, str):
        required_role_names = [required_role_names]

    for role_name in required_role_names:
        if user.eligible_for_roles.filter(name=role_name).exists():
            return True

    return False

def is_appointed_to(user, role_name, permit):
    if isinstance(role_name, str):
        if user.appointed_to.filter(permit=permit, role=Role.objects.get(name=role_name)).exists():
            return True
        else:
            return False
    else:
        raise ValueError


def is_debriefing_confirmed_by_all(permit):
    wt_members = WorkerTeam.objects.filter(permit=permit)

    for worker in wt_members:
        if worker.debriefed_general != True or worker.debriefed_specifics != True:
            return False

    return True
