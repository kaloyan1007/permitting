import json

from collections.abc import Iterable

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password

from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse

from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from .custom_forms import (
    ApplicationToFinalizeForm,
    AuthorizationForm,
    NewPermitForm,
    SingleCommentForm,
    StaffSelectionForm,
)
from .helpers_general import (
    appoint_for_duty,
    deactivate_inapplicable_action_notifs,
    get_full_permit_dict,
    has_required_role,
    is_appointed_to,
    is_debriefing_confirmed_by_all,
)

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


@login_required
def index(request):
    """
    Index view (homepage of the app for any logged in user).
    """
    user = request.user

    # Get active notifications for user - previews & counts by type
    action_notifications_count = user.action_notifications.filter(is_active=True).count()

    if action_notifications_count > 0:
        action_notifications_preview = user.action_notifications.filter(is_active=True).latest("created_on")
    else:
        action_notifications_preview = None

    info_notifications_count = user.info_notifications.filter(is_active=True).count()

    if info_notifications_count > 0:
        info_notifications_preview = user.info_notifications.filter(is_active=True).latest("created_on")
    else:
        info_notifications_preview = None

    # Get permits that user is associated with
    related_permits = [item.permit for item in Appointment.objects.filter(person=user)]
    permits_ids = set()

    for permit in related_permits:
            permits_ids.add(permit.id)

    if has_required_role(user, "worker"):
        wt_entries = user.in_workers_team.all()

        for entry in wt_entries:
            permits_ids.add(entry.permit.id)

    permits_ids = sorted(permits_ids, reverse=True)

    return render(
        request,
        "permitting/index.html",
        {
            "action_notifications_preview": action_notifications_preview,
            "info_notifications_preview": info_notifications_preview,
            "notifications_count": (action_notifications_count + info_notifications_count),
            "permits_ids": permits_ids[:3],
            "permits_count": len(permits_ids),
        },
    )


@csrf_exempt
def login_view(request):
    """
    Login route.
    """
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect(reverse("permitting:index"))
            else:
                return render(
                    request,
                    "permitting/login.html",
                    {"message": "User account is inactive."},
                )
        else:
            return render(
                request,
                "permitting/login.html",
                {"message": "Invalid username and/or password."},
            )
    else:
        return render(request, "permitting/login.html")


def logout_view(request):
    """
    Logout route
    """
    logout(request)
    return HttpResponseRedirect(reverse("permitting:index"))


@login_required
@csrf_exempt
def my_permits(request):
    """
    My Permits view, which shows a paginated list of active (or inactive) permits, associated with the logged in user.
    """
    return render(request, "permitting/my-permits.html")

def notifications(request):
    """
    Notifications view, which shows a paginated list of Action or Info notifications, associated with the logged in user.
    """
    return render(request, "permitting/notifications.html")

@login_required
@csrf_exempt
def permit_issue_new(request):
    """
    Issue New Permit view, which allows a user with `issuer` role to create a new permit.
    """
    def add_permit_many_to_manys(form, field_name, permit, model_class):
        """
        Add to the newly created permit entry values for its ManyToManyFields,
        as defined in `models.py`
        """
        if isinstance(form.cleaned_data[field_name], str):
            getattr(permit, field_name).add(
                model_class.objects.get(id=int(form.cleaned_data[field_name]))
            )
        else:
            for id in form.cleaned_data[field_name]:
                getattr(permit, field_name).add(model_class.objects.get(id=int(id)))

        return

    # Check user authorization
    user = request.user
    role_name = "issuer"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = NewPermitForm(request.POST)

        if form.is_valid():
            with transaction.atomic():
                # Create a new permit
                try:
                    permit = Permit(
                        status=PermitStatus.objects.get(id=1),
                        task_description=form.cleaned_data["task_description"],
                    )

                    # Need to save here so as to receive an id for the new permit.
                    permit.save()
                except (ValidationError, IntegrityError):
                    messages.error(request, "Failed to enter permit in DB.")
                    return render(
                        request, "permitting/issue-new.html", {"form": form}, status=400
                    )

                # Now that new permit has an id, relationships may be established
                form_field_to_model_map = [
                    {
                        "form_field_name": "collective_protection",
                        "model": CollectiveProtection,
                    },
                    {
                        "form_field_name": "personal_protection",
                        "model": PersonalProtection,
                    },
                    {"form_field_name": "risks", "model": AreaRelatedRisk},
                    {"form_field_name": "safety_measures", "model": SafetyMeasure},
                    {"form_field_name": "targeted_equipment", "model": Equipment},
                ]

                for item in form_field_to_model_map:
                    try:
                        add_permit_many_to_manys(
                            form, item["form_field_name"], permit, item["model"]
                        )

                        permit.save()
                    except (ValidationError, IntegrityError):
                        messages.error(
                            request,
                            f"Failed to add {item['form_field_name']} field to permit #{permit.id}. Appointments also not added. Please, contact admin.",
                        )
                        return render(
                            request,
                            "permitting/issue-new.html",
                            {"form": form},
                            status=400,
                        )
                # Appoint person for the position of 'issuer'
                try:
                    appoint_for_duty(permit, Role.objects.get(name="issuer"), user)
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to appoint user with id {user.id} as task issuer. Please, contact admin.",
                    )
                    return render(
                        request, "permitting/issue-new.html", {"form": form}, status=400
                    )

                # Appoint person for the position of 'task_responsible'
                try:
                    appoint_for_duty(
                        permit,
                        Role.objects.get(name="task_responsible"),
                        person=User.objects.get(
                            id=int(form.cleaned_data["task_responsible"])
                        ),
                    )
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to appoint user with id {form.cleaned_data['task_responsible']} as task_responsible. Please, contact admin.",
                    )
                    return render(
                        request, "permitting/issue-new.html", {"form": form}, status=400
                    )

                # Appoint person for the position of 'authorizer'
                try:
                    appoint_for_duty(
                        permit,
                        Role.objects.get(name="authorizer"),
                        person=User.objects.filter(
                            eligible_for_roles=Role.objects.get(name="authorizer")
                        ).first(),
                    )

                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to appoint user with id {form.cleaned_data['authorizer']} as authorizer. Please, contact admin.",
                    )
                    return render(
                        request, "permitting/issue-new.html", {"form": form}, status=400
                    )

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notification for 'task_responsible'
                action_notif = ActionNotification(
                    created_at_status=permit.status,
                    is_active=True,
                    is_read=False,
                    message=f"You're requested to fill in the staff for permit #{permit.id}.",
                    permit=permit,
                    target_viewname="permitting:permit_enter_staff",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="task_responsible")
                    ).person,
                )
                action_notif.save()

            # Redirect to view new permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request, "permitting/issue-new.html", {"form": form}, status=400
            )
    else:
        # Show page with blank form
        return render(request, "permitting/issue-new.html", {"form": NewPermitForm()})


@login_required
def permit_display(request, permit_id):
    """
    View that displays the latest version of a permit.
    """
    if request.method != "GET":
        return HttpResponse("Error: GET request required.", status=400)

    # Get latest version of permit
    if not Permit.objects.filter(id=int(permit_id)).exists():
        return render(request, "permitting/404.html")

    permit = Permit.objects.get(id=int(permit_id))

    latest_version = Contribution.objects.filter(permit=permit).latest("created_on")

    # Get active notifications for user, for permit
    action_notifications = [
        item for item in request.user.action_notifications.filter(permit=permit) if item.is_active
    ]

    return render(
        request,
        "permitting/display-permit.html",
        {
            "permit_total_content": latest_version.permit_total_content,
            "action_notifications": sorted(
                action_notifications, key=lambda notif: notif.id, reverse=True
            ),
        },
    )


@login_required
def permit_enter_staff(request, permit_id):
    """
    Enter Staff view, where a user with `task_responsible` role selects a user with role `foreman`,
    and one or more users with role `worker` to be on the team for the permit.
    """
    # Check user authorization
    user = request.user
    role_name = "task_responsible"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=1)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = StaffSelectionForm(request.POST, org=user.org)

        if form.is_valid():
            # Check workers
            for item in form.cleaned_data["workers"]:
                # Check that every worker exists as a user
                try:
                    person = User.objects.get(id=int(item))
                except User.DoesNotExist:
                    messages.error(
                        request,
                        "No user exists with one of the stated IDs. Please, try again!",
                    )
                    return render(
                        request,
                        "permitting/enter-staff-for-permit.html",
                        {"form": form, "permit_id": permit_id},
                        status=400,
                    )

                # Check if current worker is not already on the worker team for another permit
                closed_statuses = [
                    PermitStatus.objects.get(name="RJTD"),
                    PermitStatus.objects.get(name="CNLD"),
                    PermitStatus.objects.get(name="FINL"),
                ]

                for item in WorkerTeam.objects.filter(worker=person):
                    if not item.permit.status in closed_statuses:
                        messages.error(
                            request,
                            f"'{person.username}' is already on the worker team for another permit!",
                        )
                        return render(
                            request,
                            "permitting/enter-staff-for-permit.html",
                            {"form": form, "permit_id": permit_id},
                            status=400,
                        )

            # Make entries in DB
            with transaction.atomic():
                # Add entries for each worker (later to be updated with join/leave date & debrief confirmations)
                for item in form.cleaned_data["workers"]:
                    person = User.objects.get(id=int(item))

                    try:
                        wt = WorkerTeam(permit=permit, worker=person)
                        wt.save()
                    except (ValidationError, IntegrityError):
                        messages.error(
                            request,
                            f"Failed to add {person.username} as worker for permit #{permit.id}. All worker entry aborted. Please, contact admin.",
                        )
                        return render(
                            request,
                            "permitting/enter-staff-for-permit.html",
                            {"form": form, "permit_id": permit_id},
                            status=400,
                        )

                # Appoint person for the position of 'foreman'
                try:
                    appoint_for_duty(
                        permit,
                        Role.objects.get(name="foreman"),
                        person=User.objects.get(id=int(form.cleaned_data["foreman"])),
                    )

                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to appoint user with id {form.cleaned_data['foreman']} as foreman. Please, contact admin.",
                    )
                    return render(
                        request, "permitting/issue-new.html", {"form": form}, status=400
                    )

                # Update permit status
                permit.status = PermitStatus.objects.get(id=2)
                permit.save()
                deactivate_inapplicable_action_notifs(permit)

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notification for 'authorizer'
                action_notif = ActionNotification(
                    created_at_status=permit.status,
                    is_active=True,
                    is_read=False,
                    message=f"You're requested to authorize permit #{permit.id}.",
                    permit=permit,
                    target_viewname="permitting:permit_authorize",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="authorizer")
                    ).person,
                )
                action_notif.save()

                # Create notification for 'issuer'
                info_notif = InfoNotification(
                    is_active=True,
                    is_read=False,
                    message=f"Staff has been filled-in, and permit #{permit.id} has been submitted for authorization.",
                    permit=permit,
                    target_viewname="permitting:permit_display",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="issuer")
                    ).person,
                )
                info_notif.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/enter-staff-for-permit.html",
                {"form": form, "permit_id": permit_id},
                status=400,
            )
    else:
        # Show page with blank form
        return render(
            request,
            "permitting/enter-staff-for-permit.html",
            {"form": StaffSelectionForm(org=user.org), "permit_id": permit_id},
        )


@login_required
def permit_authorize(request, permit_id):
    """
    Authorize view, which allows a user with `authorizer` role to either:
    - authorize a permit (releasing it for application of Lockout & Tagout), or
    - reject it (ending the flow for this permit).
    """
    # Check user authorization
    user = request.user
    role_name = "authorizer"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=2)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = AuthorizationForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Appoint person for the position of 'loto_officer'
                try:
                    appoint_for_duty(
                        permit,
                        Role.objects.get(name="loto_officer"),
                        person=User.objects.get(
                            id=int(form.cleaned_data["loto_officer"])
                        ),
                    )
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to appoint user with id {form.cleaned_data['loto_officer']} as loto_officer. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/authorize-permit.html",
                        {"form": form, "permit_id": permit_id},
                        status=400,
                    )

                # Appoint person for the position of 'safety_gatekeeper'
                try:
                    appoint_for_duty(
                        permit,
                        Role.objects.get(name="safety_gatekeeper"),
                        person=User.objects.get(
                            id=int(form.cleaned_data["safety_gatekeeper"])
                        ),
                    )
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to appoint user with id {form.cleaned_data['safety_gatekeeper']} as safety_gatekeeper. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/authorize-permit.html",
                        {"form": form, "permit_id": permit_id},
                        status=400,
                    )

                # Add 'initialization_ok' general confirmation
                confirmation_short_desc = "initialization_ok"
                try:
                    confm = Confirmation(
                        confirmed=True,
                        permit=permit,
                        what=ConfirmationEvent.objects.get(
                            short_description=confirmation_short_desc
                        ),
                    )
                    confm.save()
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/authorize-permit.html",
                        {"form": form, "permit_id": permit_id},
                        status=400,
                    )

                # Update permit status
                permit.status = PermitStatus.objects.get(id=3)
                permit.save()
                deactivate_inapplicable_action_notifs(permit)

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notification for 'loto_officer'
                action_notif = ActionNotification(
                    created_at_status=permit.status,
                    is_active=True,
                    is_read=False,
                    message=f"You're requested to perform LOTO activities for permit #{permit.id}.",
                    permit=permit,
                    target_viewname="permitting:permit_add_loto",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="loto_officer")
                    ).person,
                )
                action_notif.save()

                # Create notifications for 'issuer' and 'task_responsible'
                for role_name in ["issuer", "task_responsible"]:
                    info_notif = InfoNotification(
                        is_active=True,
                        is_read=False,
                        message=f"Permit #{permit.id} has been authorized.",
                        permit=permit,
                        target_viewname="permitting:permit_display",
                        user=permit.appointments.get(
                            role=Role.objects.get(name=role_name)
                        ).person,
                    )
                    info_notif.save()

                # Create notifications for 'foreman' and 'safety_gatekeeper'
                for role_name in ["foreman", "safety_gatekeeper"]:
                    info_notif = InfoNotification(
                        is_active=True,
                        is_read=False,
                        message=f"You've been appointed as '{role_name}' for permit #{permit.id}. LOTO activities for the permit are underway.",
                        permit=permit,
                        target_viewname="permitting:permit_display",
                        user=permit.appointments.get(
                            role=Role.objects.get(name=role_name)
                        ).person,
                    )
                    info_notif.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/authorize-permit.html",
                {"form": form, "permit_id": permit_id},
                status=400,
            )
    else:
        # Show page with blank form
        return render(
            request,
            "permitting/authorize-permit.html",
            {"form": AuthorizationForm(), "permit_id": permit_id},
        )


@login_required
def permit_reject(request, permit_id):
    """
    Route for rejecting a permit. Used by user with `authorizer` role,
    it flags the particular permit as rejected and ends the flow for it.
    """
    if request.method != "POST":
        return HttpResponse(
            "Error: POST request required.",
            status=400,
        )

    # Check user authorization
    user = request.user
    role_name = "authorizer"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=2)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    # Check if a rejection_comment was submitted
    if not request.POST.get("rejection_comment"):
        return HttpResponse(
            f"Error: Must provide Rejection comment.",
            status=400,
        )

    # Make entries in DB
    with transaction.atomic():
        # Update permit status
        permit.status = PermitStatus.objects.get(id=4)
        permit.save()
        deactivate_inapplicable_action_notifs(permit)

        # Save the permit version
        contribution = Contribution(
            author=user,
            comment=request.POST.get("rejection_comment").strip(),
            permit=permit,
            permit_total_content=get_full_permit_dict(permit),
        )
        contribution.save()

        # Create notifications for 'issuer' and 'task_responsible'
        for role_name in ["issuer", "task_responsible"]:
            info_notif = InfoNotification(
                is_active=True,
                is_read=False,
                message=f"Permit #{permit.id} has been rejected by authorizer. See rejection comment on permit's page.",
                permit=permit,
                target_viewname="permitting:permit_display",
                user=permit.appointments.get(
                    role=Role.objects.get(name=role_name)
                ).person,
            )
            info_notif.save()

    # Redirect to view permit
    return HttpResponseRedirect(
        reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
    )


@login_required
def permit_add_loto(request, permit_id):
    """
    Add Lockout & Tagout view, where a user with `loto_officer` role confirms to have applied Lockout & Tagout.
    """
    # Check user authorization
    user = request.user
    role_name = "loto_officer"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=3)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Add 'loto_in_place' general confirmation
                confirmation_short_desc = "loto_in_place"
                try:
                    confm = Confirmation(
                        confirmed=True,
                        permit=permit,
                        what=ConfirmationEvent.objects.get(
                            short_description=confirmation_short_desc
                        ),
                    )
                    confm.save()
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/add-loto.html",
                        {
                            "form": form,
                            "loto_activities": permit.safety_measures.all(),
                            "permit_id": permit_id,
                        },
                        status=400,
                    )

                # Update permit status
                permit.status = PermitStatus.objects.get(id=5)
                permit.save()
                deactivate_inapplicable_action_notifs(permit)

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notification for 'safety_gatekeeper'
                action_notif = ActionNotification(
                    created_at_status=permit.status,
                    is_active=True,
                    is_read=False,
                    message=f"You're requested to check LOTO for permit #{permit.id} & perform general safety debriefing.",
                    permit=permit,
                    target_viewname="permitting:permit_safety_gk",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="safety_gatekeeper")
                    ).person,
                )
                action_notif.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/add-loto.html",
                {
                    "form": form,
                    "loto_activities": permit.safety_measures.all(),
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/add-loto.html",
            {
                "form": SingleCommentForm(),
                "loto_activities": permit.safety_measures.all(),
                "permit_id": permit_id,
            },
        )


@login_required
def permit_safety_gk(request, permit_id):
    """
    Safety Gatekeeping view, where a user with `safety_gatekeeper` role confirms
    to have personally checked the Lockout & Tagout procedures are applied, as specified in the permit.
    """
    # Check user authorization
    user = request.user
    role_name = "safety_gatekeeper"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=5)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Add 'performed_general_safety_briefing' general confirmation
                confirmation_short_desc = "performed_general_safety_briefing"
                try:
                    confm = Confirmation(
                        confirmed=True,
                        permit=permit,
                        what=ConfirmationEvent.objects.get(
                            short_description=confirmation_short_desc
                        ),
                    )
                    confm.save()
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/safety-gk.html",
                        {
                            "form": form,
                            "loto_activities": permit.safety_measures.all(),
                            "collective_protections": permit.collective_protection.all(),
                            "worker_team": WorkerTeam.objects.filter(permit=permit),
                            "permit_id": permit_id,
                        },
                        status=400,
                    )

                # Update permit status
                permit.status = PermitStatus.objects.get(id=6)
                permit.save()
                deactivate_inapplicable_action_notifs(permit)

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notification for 'task_responsible'
                action_notif = ActionNotification(
                    created_at_status=permit.status,
                    is_active=True,
                    is_read=False,
                    message=f"You're requested to give general task instruction to the team for permit #{permit.id}.",
                    permit=permit,
                    target_viewname="permitting:permit_task_instruction",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="task_responsible")
                    ).person,
                )
                action_notif.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/safety-gk.html",
                {
                    "form": form,
                    "loto_activities": permit.safety_measures.all(),
                    "collective_protections": permit.collective_protection.all(),
                    "worker_team": WorkerTeam.objects.filter(permit=permit),
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/safety-gk.html",
            {
                "form": SingleCommentForm(),
                "loto_activities": permit.safety_measures.all(),
                "collective_protections": permit.collective_protection.all(),
                "worker_team": WorkerTeam.objects.filter(permit=permit),
                "permit_id": permit_id,
            },
        )


@login_required
def permit_task_instruction(request, permit_id):
    """
    Task Instruction view, where a user with `task_responsible` role confirms to have instructed the whole worker team on the task-specific risks.
    """
    # Check user authorization
    user = request.user
    role_name = "task_responsible"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=6)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Add 'performed_task_specific_briefing' general confirmation
                confirmation_short_desc = "performed_task_specific_briefing"
                try:
                    confm = Confirmation(
                        confirmed=True,
                        permit=permit,
                        what=ConfirmationEvent.objects.get(
                            short_description=confirmation_short_desc
                        ),
                    )
                    confm.save()
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/task-instruction.html",
                        {
                            "form": form,
                            "task_description": permit.task_description,
                            "worker_team": WorkerTeam.objects.filter(permit=permit),
                            "permit_id": permit_id,
                        },
                        status=400,
                    )

                # Update permit status
                permit.status = PermitStatus.objects.get(id=7)
                permit.save()
                deactivate_inapplicable_action_notifs(permit)

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notifications for workers
                for entry in WorkerTeam.objects.filter(permit=permit):
                    action_notif = ActionNotification(
                        created_at_status=permit.status,
                        is_active=True,
                        is_read=False,
                        message=f"You're requested to confirm being debriefed for permit #{permit.id}.",
                        permit=permit,
                        target_viewname="permitting:permit_confirm_debriefing",
                        user=entry.worker,
                    )
                    action_notif.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/task-instruction.html",
                {
                    "form": form,
                    "task_description": permit.task_description,
                    "worker_team": WorkerTeam.objects.filter(permit=permit),
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/task-instruction.html",
            {
                "form": SingleCommentForm(),
                "task_description": permit.task_description,
                "worker_team": WorkerTeam.objects.filter(permit=permit),
                "permit_id": permit_id,
            },
        )


@login_required
def permit_confirm_debriefing(request, permit_id):
    """
    Confirm Debriefing view, where users with `worker` role confirm to have been debriefed,
    both on the area & equipment related risks, and the task-specific hazards for the work they're about to perform.
    """
    # Check user authorization
    user = request.user
    role_name = "worker"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=7)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check worker is on team for permit
    if not user.in_workers_team.filter(permit=permit).exists():
        return HttpResponse(
            f"Error: You're not listed on the workers team for this permit.",
            status=400,
        )

    # Check worker hasn't already confirmed
    wt_member = WorkerTeam.objects.get(permit=permit, worker=user)

    if wt_member.debriefed_general == True and wt_member.debriefed_specifics == True:
        return HttpResponse(
            f"Error: You've already confirmed to have been debriefed on area & equipment + task-specific hazards for this permit.",
            status=403,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Record confirmations for debriefings
                try:
                    wt_member.debriefed_general = True
                    wt_member.debriefed_specifics = True
                    wt_member.save()
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to record confirmations for debriefings in workteam member id: {wt_member.id}. All actions aborted. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/confirm-debriefing.html",
                        {
                            "form": form,
                            "task_description": permit.task_description,
                            "permit_id": permit_id,
                        },
                        status=400,
                    )

                # Update permit status
                if is_debriefing_confirmed_by_all(permit):
                    permit.status = PermitStatus.objects.get(id=8)
                    permit.save()
                    deactivate_inapplicable_action_notifs(permit)

                    # Create notification for 'safety_gatekeeper'
                    action_notif = ActionNotification(
                        created_at_status=permit.status,
                        is_active=True,
                        is_read=False,
                        message=f"You're requested to confirm that workers may be allowed to the workplace for permit #{permit.id}.",
                        permit=permit,
                        target_viewname="permitting:permit_open_for_day",
                        user=permit.appointments.get(
                            role=Role.objects.get(name="safety_gatekeeper")
                        ).person,
                    )
                    action_notif.save()

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/confirm-debriefing.html",
                {
                    "form": form,
                    "task_description": permit.task_description,
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/confirm-debriefing.html",
            {
                "form": SingleCommentForm(),
                "task_description": permit.task_description,
                "permit_id": permit_id,
            },
        )


@login_required
def permit_open_for_day(request, permit_id):
    """
    Open For Workday view, where first a user with `safety_gatekeeper` role confirms that the safety measures are in place,
    and then a user with `foreman` role confirms to have led the workers into the work area.
    """
    # Check user authorization
    user = request.user
    role_names = ["safety_gatekeeper", "foreman"]

    if not has_required_role(user, role_names):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with roles '{role_names}'",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    acceptable_statuses = [
        PermitStatus.objects.get(id=8),
        PermitStatus.objects.get(id=10),
    ]
    if not permit.status in acceptable_statuses:
        return HttpResponse(
            f"Error: The permit needs to have status in range '{[item.name for item in acceptable_statuses]}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    users_appointments = []

    for role_name in role_names:
        if is_appointed_to(user, role_name, permit):
            users_appointments.append(role_name)

    if len(users_appointments) == 0:
        return HttpResponse(
            f"Error: You're not listed on the team as {role_names} for this permit.",
            status=400,
        )

    # Check user hasn't already confirmed
    try:
        oc_entry = DailyOpenClose.objects.filter(
            permit=permit, opened_at=None, closed_at=None
        ).latest("id")
    except DailyOpenClose.DoesNotExist:
        oc_entry = None

    if oc_entry:
        if (
            oc_entry.confirmed_loto_in_place
            and "safety_gatekeeper" in users_appointments
        ) or (oc_entry.confirmed_led_workers_in and "foreman" in users_appointments):
            return HttpResponse(
                f"Error: You've already commited the required confirmation for openning this permit for the workday.",
                status=403,
            )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Create a daily open/close entry if necessary
                if not oc_entry:
                    oc_entry = DailyOpenClose(permit=permit)
                    oc_entry.save()

                # Record confirmations
                if (
                    not oc_entry.confirmed_loto_in_place
                    and "safety_gatekeeper" in users_appointments
                ):
                    try:
                        oc_entry.confirmed_loto_in_place = True
                        oc_entry.save()
                    except (ValidationError, IntegrityError):
                        messages.error(
                            request,
                            "Failed to record confirmation 'confirmed_loto_in_place'. All actions aborted. Please, contact admin.",
                        )
                        return render(
                            request,
                            "permitting/open-for-workday.html",
                            {
                                "appointments": users_appointments,
                                "form": form,
                                "task_description": permit.task_description,
                                "permit_id": permit_id,
                            },
                            status=400,
                        )
                    else:
                        # Deactivate notification for 'safety_gatekeeper'
                        inapplicable_notif = ActionNotification.objects.get(
                            created_at_status=permit.status,
                            is_active=True,
                            permit=permit,
                            user=permit.appointments.get(
                                role=Role.objects.get(name="safety_gatekeeper")
                            ).person,
                        )
                        inapplicable_notif.is_active = False
                        inapplicable_notif.save()

                        # Create notification for 'foreman'
                        action_notif = ActionNotification(
                            created_at_status=permit.status,
                            is_active=True,
                            is_read=False,
                            message=f"You're requested to confirm that workers were led into the workplace for permit #{permit.id}.",
                            permit=permit,
                            target_viewname="permitting:permit_open_for_day",
                            user=permit.appointments.get(
                                role=Role.objects.get(name="foreman")
                            ).person,
                        )
                        action_notif.save()

                if (
                    not oc_entry.confirmed_led_workers_in
                    and "foreman" in users_appointments
                ):
                    # Make sure 'foreman' can confirm workers are led in only after 'safety_gatekeeper' confirms LOTO
                    if not oc_entry.confirmed_loto_in_place:
                        return HttpResponse(
                            f"Error: The safety_gatekeeper has to first confirm that LOTO is in place.",
                            status=403,
                        )
                    else:
                        try:
                            oc_entry.confirmed_led_workers_in = True
                            oc_entry.save()
                        except (ValidationError, IntegrityError):
                            messages.error(
                                request,
                                "Failed to record confirmation 'confirmed_led_workers_in'. All actions aborted. Please, contact admin.",
                            )
                            return render(
                                request,
                                "permitting/open-for-workday.html",
                                {
                                    "appointments": users_appointments,
                                    "form": form,
                                    "task_description": permit.task_description,
                                    "permit_id": permit_id,
                                },
                                status=400,
                            )
                # Record permit as opened if all conditions are satisfied
                if (
                    oc_entry.confirmed_loto_in_place
                    and oc_entry.confirmed_led_workers_in
                ) and (not oc_entry.opened_at and not oc_entry.closed_at):
                    # Record opening in open/close entry
                    oc_entry.opened_at = timezone.now()
                    oc_entry.save()

                    # Update permit status
                    permit.status = PermitStatus.objects.get(id=9)
                    permit.save()
                    deactivate_inapplicable_action_notifs(permit)

                    # Create notification for 'foreman'
                    action_notif = ActionNotification(
                        created_at_status=permit.status,
                        is_active=True,
                        is_read=False,
                        message=f"Once work for the day is done, you're requested to confirm that workers were led out of the workplace for permit #{permit.id}.",
                        permit=permit,
                        target_viewname="permitting:permit_close_for_day",
                        user=permit.appointments.get(
                            role=Role.objects.get(name="foreman")
                        ).person,
                    )
                    action_notif.save()

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Redirect to view permit
                return HttpResponseRedirect(
                    reverse(
                        "permitting:permit_display", kwargs={"permit_id": permit.id}
                    )
                )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/open-for-workday.html",
                {
                    "appointments": users_appointments,
                    "form": form,
                    "task_description": permit.task_description,
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/open-for-workday.html",
            {
                "appointments": users_appointments,
                "form": SingleCommentForm(),
                "task_description": permit.task_description,
                "permit_id": permit_id,
            },
        )


@login_required
def permit_close_for_day(request, permit_id):
    """
    Close For Workday view, where first a user with `foreman` role confirms to have led the workers out of the work area,
    and then a user with `safety_gatekeeper` role verifies.
    """
    # Check user authorization
    user = request.user
    role_names = ["safety_gatekeeper", "foreman"]

    if not has_required_role(user, role_names):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with roles '{role_names}'",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=9)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    users_appointments = []

    for role_name in role_names:
        if is_appointed_to(user, role_name, permit):
            users_appointments.append(role_name)

    if len(users_appointments) == 0:
        return HttpResponse(
            f"Error: You're not listed on the team as {role_names} for this permit.",
            status=400,
        )

    # Check user hasn't already confirmed
    try:
        oc_entry = DailyOpenClose.objects.filter(permit=permit, closed_at=None).latest(
            "id"
        )
    except DailyOpenClose.DoesNotExist:
        return HttpResponse(
            f"Error: No entry of this permit for being opened the workday. Contact admin.",
            status=403,
        )
    else:
        if oc_entry.confirmed_led_workers_out and "foreman" in users_appointments:
            return HttpResponse(
                f"Error: You've already commited the required confirmation for closing this permit for the workday.",
                status=403,
            )

    # Make sure 'safety_gatekeeper' can confirm workers are led out only after 'foreman' confirms
    if (
        not oc_entry.confirmed_led_workers_out
        and "safety_gatekeeper" in users_appointments
    ):
        return HttpResponse(
            f"Error: The foreman has to first confirm that the workers have been led out of the workplace.",
            status=403,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Record confirmations
                if (
                    not oc_entry.confirmed_led_workers_out
                    and "foreman" in users_appointments
                ):
                    try:
                        oc_entry.confirmed_led_workers_out = True
                        oc_entry.save()
                    except (ValidationError, IntegrityError):
                        messages.error(
                            request,
                            "Failed to record confirmation 'confirmed_led_workers_out'. All actions aborted. Please, contact admin.",
                        )
                        return render(
                            request,
                            "permitting/close-for-workday.html",
                            {
                                "appointments": users_appointments,
                                "form": form,
                                "task_description": permit.task_description,
                                "permit_id": permit_id,
                            },
                            status=400,
                        )
                    else:
                        # Deactivate notification for 'foreman'
                        inapplicable_notif = ActionNotification.objects.get(
                            created_at_status=permit.status,
                            is_active=True,
                            permit=permit,
                            user=permit.appointments.get(
                                role=Role.objects.get(name="foreman")
                            ).person,
                        )
                        inapplicable_notif.is_active = False
                        inapplicable_notif.save()

                        # Create notification for 'safety_gatekeeper'
                        action_notif = ActionNotification(
                            created_at_status=permit.status,
                            is_active=True,
                            is_read=False,
                            message=f"You're requested to confirm that workers were led out of the workplace for permit #{permit.id}.",
                            permit=permit,
                            target_viewname="permitting:permit_close_for_day",
                            user=permit.appointments.get(
                                role=Role.objects.get(name="safety_gatekeeper")
                            ).person,
                        )
                        action_notif.save()

                # Record permit as closed if all conditions are satisfied
                if (
                    oc_entry.confirmed_led_workers_out
                    and "safety_gatekeeper" in users_appointments
                ) and not oc_entry.closed_at:
                    # Record opening in open/close entry
                    oc_entry.closed_at = timezone.now()
                    oc_entry.save()

                    # Update permit status
                    permit.status = PermitStatus.objects.get(id=10)
                    permit.save()
                    deactivate_inapplicable_action_notifs(permit)

                    # Create notification for 'safety_gatekeeper'
                    action_notif = ActionNotification(
                        created_at_status=permit.status,
                        is_active=True,
                        is_read=False,
                        message=f"If necessary to open the permit for another day, you can confirm that workers may be allowed to the workplace for permit #{permit.id}.",
                        permit=permit,
                        target_viewname="permitting:permit_open_for_day",
                        user=permit.appointments.get(
                            role=Role.objects.get(name="safety_gatekeeper")
                        ).person,
                    )
                    action_notif.save()

                    # Create notification for 'task_responsible'
                    action_notif = ActionNotification(
                        created_at_status=permit.status,
                        is_active=True,
                        is_read=False,
                        message=f"If work on permit #{permit.id} is technically completed, you can apply for finalization of the permit.",
                        permit=permit,
                        target_viewname="permitting:permit_apply_for_finalization",
                        user=permit.appointments.get(
                            role=Role.objects.get(name="task_responsible")
                        ).person,
                    )
                    action_notif.save()

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Redirect to view permit
                return HttpResponseRedirect(
                    reverse(
                        "permitting:permit_display", kwargs={"permit_id": permit.id}
                    )
                )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/close-for-workday.html",
                {
                    "appointments": users_appointments,
                    "form": form,
                    "task_description": permit.task_description,
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/close-for-workday.html",
            {
                "appointments": users_appointments,
                "form": SingleCommentForm(),
                "task_description": permit.task_description,
                "permit_id": permit_id,
            },
        )


@login_required
def permit_apply_for_finalization(request, permit_id):
    """
    Apply For Finalization view, where a user with `task_responsible` role submits the permit for review before finalization.
    """
    # Check user authorization
    user = request.user
    role_name = "task_responsible"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=10)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = ApplicationToFinalizeForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Add general confirmations
                confirmation_short_descriptions = [
                    "task_completed",
                    "workplace_cleaned",
                    "eq_safe_to_operate",
                ]
                for confirmation_short_desc in confirmation_short_descriptions:
                    # Try and get existing confirmation
                    try:
                        confm = Confirmation.objects.get(
                            permit=permit,
                            what=ConfirmationEvent.objects.get(
                                short_description=confirmation_short_desc
                            ),
                        )
                    except Confirmation.DoesNotExist:
                        # Try to create a new confirmation, since one like it doesn't yet exist for permit
                        try:
                            confm = Confirmation(
                                confirmed=True,
                                permit=permit,
                                what=ConfirmationEvent.objects.get(
                                    short_description=confirmation_short_desc
                                ),
                            )
                            confm.save()
                        except (ValidationError, IntegrityError):
                            messages.error(
                                request,
                                f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                            )
                            return render(
                                request,
                                "permitting/apply-for-finalization.html",
                                {
                                    "form": form,
                                    "task_description": permit.task_description,
                                    "permit_id": permit_id,
                                },
                                status=400,
                            )
                    else:
                        # Mark confirmation as success
                        try:
                            confm.confirmed = True
                            confm.save()
                        except (ValidationError, IntegrityError):
                            messages.error(
                                request,
                                f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                            )
                            return render(
                                request,
                                "permitting/apply-for-finalization.html",
                                {
                                    "form": form,
                                    "task_description": permit.task_description,
                                    "permit_id": permit_id,
                                },
                                status=400,
                            )

                # Record tech completion timedate
                permit.tech_completion_time = timezone.now()
                permit.save()

                # Record tests & go-live procedures comment
                permit.tests_and_golive_comment = form.cleaned_data[
                    "performed_tests_and_golive_procedures_description"
                ]
                permit.save()

                # Update permit status
                permit.status = PermitStatus.objects.get(id=11)
                permit.save()
                deactivate_inapplicable_action_notifs(permit)

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notification for 'authorizer'
                action_notif = ActionNotification(
                    created_at_status=permit.status,
                    is_active=True,
                    is_read=False,
                    message=f"You're requested to review an application for finalization of permit #{permit.id}.",
                    permit=permit,
                    target_viewname="permitting:permit_review_finalization_application",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="authorizer")
                    ).person,
                )
                action_notif.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/apply-for-finalization.html",
                {
                    "form": form,
                    "task_description": permit.task_description,
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/apply-for-finalization.html",
            {
                "form": ApplicationToFinalizeForm(),
                "task_description": permit.task_description,
                "permit_id": permit_id,
            },
        )


@login_required
def permit_review_finalization_application(request, permit_id):
    """
    Review Finalization Application view, where a user with `authorizer` role can review a permit that has been applied for finalization, and either:
    - refuse to finalize now (thus returning it to the `task_responsible`), or
    - send the permit for Lockout & Tagout removal, or
    - finalize the permit, while keeping Lockout & Tagout in place.
    """
    # Check user authorization
    user = request.user
    role_name = "authorizer"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=11)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Add 'allowed_loto_removal' general confirmation
                confirmation_short_desc = "allowed_loto_removal"
                try:
                    confm = Confirmation(
                        confirmed=True,
                        permit=permit,
                        what=ConfirmationEvent.objects.get(
                            short_description=confirmation_short_desc
                        ),
                    )
                    confm.save()
                except (ValidationError, IntegrityError):
                    messages.error(
                        request,
                        f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                    )
                    return render(
                        request,
                        "permitting/review-finalization-application.html",
                        {
                            "form": form,
                            "permit_id": permit_id,
                        },
                        status=400,
                    )

                # Update permit status
                permit.status = PermitStatus.objects.get(id=12)
                permit.save()
                deactivate_inapplicable_action_notifs(permit)

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Create notification for 'loto_officer'
                action_notif = ActionNotification(
                    created_at_status=permit.status,
                    is_active=True,
                    is_read=False,
                    message=f"You're requested to remove LOTO for permit #{permit.id}.",
                    permit=permit,
                    target_viewname="permitting:permit_remove_loto",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="loto_officer")
                    ).person,
                )
                action_notif.save()

                # Create notification for 'task_responsible'
                info_notif = InfoNotification(
                    is_active=True,
                    is_read=False,
                    message=f"Permit #{permit.id} has been approved. LOTO removal is underway",
                    permit=permit,
                    target_viewname="permitting:permit_display",
                    user=permit.appointments.get(
                        role=Role.objects.get(name="task_responsible")
                    ).person,
                )
                info_notif.save()

            # Redirect to view permit
            return HttpResponseRedirect(
                reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
            )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/review-finalization-application.html",
                {
                    "form": form,
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/review-finalization-application.html",
            {
                "form": SingleCommentForm(),
                "permit_id": permit_id,
            },
        )


@login_required
def permit_refuse_finalization(request, permit_id):
    """
    Route that a user with `authorizer` role uses in order to refuse finalize a permit that has been submitted for finalization.
    The permit is then returned to the `task_responsible`, who can either:
    - reopen it for another day/s, and do additional work, or
    - better justify the case for finalizing.
    """
    if request.method != "POST":
        return HttpResponse("Error: POST request required.", status=400)

    # Check user authorization
    user = request.user
    role_name = "authorizer"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=11)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    # Check if a refuse_finalization_comment was submitted
    if not request.POST.get("refuse_finalization_comment"):
        return HttpResponse(
            f"Error: Must provide Finalization Refusal comment.",
            status=400,
        )

    # Make entries in DB
    with transaction.atomic():
        # Reverse general confirmations
        confirmation_short_descriptions = [
            "task_completed",
            "workplace_cleaned",
            "eq_safe_to_operate",
        ]
        for confirmation_short_desc in confirmation_short_descriptions:
            try:
                confm = Confirmation.objects.get(
                    permit=permit,
                    what=ConfirmationEvent.objects.get(
                        short_description=confirmation_short_desc
                    ),
                )
            except Confirmation.DoesNotExist:
                pass
            else:
                try:
                    confm.confirmed = False
                    confm.save()
                except (ValidationError, IntegrityError):
                    return HttpResponse(
                        f"Error: Failed to clear '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                        status=400,
                    )

        # Clear tech completion timedate
        permit.tech_completion_time = None
        permit.save()

        # Clear tests & go-live procedures comment
        permit.tests_and_golive_comment = ""
        permit.save()

        # Deactivate notification for 'authorizer' (needs to be done before reverting status !!!)
        inapplicable_notif = ActionNotification.objects.get(
            created_at_status=permit.status,
            is_active=True,
            permit=permit,
            user=permit.appointments.get(
                role=Role.objects.get(name="authorizer")
            ).person,
        )
        inapplicable_notif.is_active = False
        inapplicable_notif.save()

        # Revert permit status
        permit.status = PermitStatus.objects.get(id=10)
        permit.save()

        # Save the permit version
        contribution = Contribution(
            author=user,
            comment=request.POST.get("refuse_finalization_comment").strip(),
            permit=permit,
            permit_total_content=get_full_permit_dict(permit),
        )
        contribution.save()

        # Create notification for 'task_responsible'
        action_notif = ActionNotification(
            created_at_status=permit.status,
            is_active=True,
            is_read=False,
            message=f"Authorizer refused to approve finalization of permit #{permit.id}. Please, check refusal comment. If necessary contact 'safety_gatekeeper' to reopen the permit.",
            permit=permit,
            target_viewname="permitting:permit_apply_for_finalization",
            user=permit.appointments.get(
                role=Role.objects.get(name="task_responsible")
            ).person,
        )
        action_notif.save()

        # Create notification for 'safety_gatekeeper'
        action_notif = ActionNotification(
            created_at_status=permit.status,
            is_active=True,
            is_read=False,
            message=f"Authorizer refused to approve finalization of permit #{permit.id}. If 'task_responsible' needs the permit to be opened for the day, confirm that workers may be allowed to the workplace.",
            permit=permit,
            target_viewname="permitting:permit_open_for_day",
            user=permit.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
            ).person,
        )
        action_notif.save()

    # Redirect to view permit
    return HttpResponseRedirect(
        reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
    )


@login_required
def permit_remove_loto(request, permit_id):
    """
    Remove Lockout & Tagout view, where first a user with `loto_officer` role confirms to have removed Lockout & Tagout,
    and then a user with `safety_gatekeeper` role verifies. After the actions of both are completed, the permit gets finalized.
    """
    # Check user authorization
    user = request.user
    role_names = ["loto_officer", "safety_gatekeeper"]

    if not has_required_role(user, role_names):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with roles '{role_names}'",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=12)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    users_appointments = []

    for role_name in role_names:
        if is_appointed_to(user, role_name, permit):
            users_appointments.append(role_name)

    if len(users_appointments) == 0:
        return HttpResponse(
            f"Error: You're not listed on the team as {role_names} for this permit.",
            status=400,
        )

    # Check user hasn't already confirmed
    # (only done for "loto_officer", since if "safety_gatekeeper" had confirmed, the status would have been changed)
    loto_removed_ce = ConfirmationEvent.objects.get(short_description="loto_removed")

    if Confirmation.objects.filter(
        confirmed=True,
        permit=permit,
        what=loto_removed_ce,
    ).exists():
        if "loto_officer" in users_appointments:
            return HttpResponse(
                f"Error: You've already commited the required confirmation.",
                status=403,
            )
    else:
        # Make sure 'safety_gatekeeper' can confirm only after 'loto_officer' confirms
        if "safety_gatekeeper" in users_appointments:
            return HttpResponse(
                f"Error: The LOTO officer has to first confirm that Lockout & Tagout has been removed from the equipment.",
                status=403,
            )

    if request.method == "POST":
        # Retrieve populated form
        form = SingleCommentForm(request.POST)

        if form.is_valid():
            # Make entries in DB
            with transaction.atomic():
                # Record confirmations
                if "loto_officer" in users_appointments:
                    try:
                        confm = Confirmation.objects.get(
                            permit=permit,
                            what=loto_removed_ce,
                        )
                    except Confirmation.DoesNotExist:
                        confm = Confirmation(
                            confirmed=True,
                            permit=permit,
                            what=loto_removed_ce,
                        )
                        confm.save()
                    else:
                        try:
                            confm.confirmed = True
                            confm.save()
                        except (ValidationError, IntegrityError):
                            messages.error(
                                request,
                                f"Error: Failed to record '{loto_removed_ce.short_description}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                            )
                            return render(
                                request,
                                "permitting/remove-loto.html",
                                {
                                    "appointments": users_appointments,
                                    "form": form,
                                    "loto_activities": permit.safety_measures.all(),
                                    "permit_id": permit_id,
                                },
                                status=400,
                            )

                    # Deactivate notification for 'loto_officer'
                    inapplicable_notif = ActionNotification.objects.get(
                        created_at_status=permit.status,
                        is_active=True,
                        permit=permit,
                        user=permit.appointments.get(
                            role=Role.objects.get(name="loto_officer")
                        ).person,
                    )
                    inapplicable_notif.is_active = False
                    inapplicable_notif.save()

                    # Create notification for 'safety_gatekeeper'
                    action_notif = ActionNotification(
                        created_at_status=permit.status,
                        is_active=True,
                        is_read=False,
                        message=f"You're requested to confirm LOTO removal for permit #{permit.id}.",
                        permit=permit,
                        target_viewname="permitting:permit_remove_loto",
                        user=permit.appointments.get(
                            role=Role.objects.get(name="safety_gatekeeper")
                        ).person,
                    )
                    action_notif.save()

                # Update permit status
                if "safety_gatekeeper" in users_appointments:
                    if Confirmation.objects.filter(
                        confirmed=True,
                        permit=permit,
                        what=loto_removed_ce,
                    ).exists():
                        permit.status = PermitStatus.objects.get(id=13)
                        permit.save()
                        deactivate_inapplicable_action_notifs(permit)

                        # Create notifications for permit finalization
                        for role in Role.objects.exclude(name="worker"):
                            info_notif = InfoNotification(
                                is_active=True,
                                is_read=False,
                                message=f"Permit #{permit.id} has been finalized and LOTO has been removed.",
                                permit=permit,
                                target_viewname="permitting:permit_display",
                                user=permit.appointments.get(role=role).person,
                            )
                            info_notif.save()

                        for entry in WorkerTeam.objects.filter(permit=permit):
                            info_notif = InfoNotification(
                                is_active=True,
                                is_read=False,
                                message=f"Permit #{permit.id} has been finalized and LOTO has been removed.",
                                permit=permit,
                                target_viewname="permitting:permit_display",
                                user=entry.worker,
                            )
                            info_notif.save()

                # Save the permit version
                contribution = Contribution(
                    author=user,
                    comment=form.cleaned_data["comment"],
                    permit=permit,
                    permit_total_content=get_full_permit_dict(permit),
                )
                contribution.save()

                # Redirect to view permit
                return HttpResponseRedirect(
                    reverse(
                        "permitting:permit_display", kwargs={"permit_id": permit.id}
                    )
                )
        else:
            # Return back populated form
            messages.error(request, "Invalid input")
            return render(
                request,
                "permitting/remove-loto.html",
                {
                    "appointments": users_appointments,
                    "form": form,
                    "loto_activities": permit.safety_measures.all(),
                    "permit_id": permit_id,
                },
                status=400,
            )
    else:
        return render(
            request,
            "permitting/remove-loto.html",
            {
                "appointments": users_appointments,
                "form": SingleCommentForm(),
                "loto_activities": permit.safety_measures.all(),
                "permit_id": permit_id,
            },
        )


@login_required
def permit_finalize(request, permit_id):
    """
    Route that a user with `authorizer` role uses to finalize a permit.
    """
    if request.method != "POST":
        return HttpResponse(f"Error: POST request required", status=400)

    # Check user authorization
    user = request.user
    role_name = "authorizer"

    if not has_required_role(user, role_name):
        return HttpResponse(
            f"Error: You're not authorized to use this page. Only available for users with '{role_name}' role",
            status=403,
        )

    # Retrieve permit
    try:
        permit = Permit.objects.get(id=int(permit_id))
    except (ValueError, Permit.DoesNotExist):
        messages.error(request, "No permit with the stated id exists.")
        return HttpResponse(
            f"Error: No permit with the stated id exists.",
            status=400,
        )

    # Check if permit has the right status for this route's operations
    required_status = PermitStatus.objects.get(id=11)
    if permit.status != required_status:
        return HttpResponse(
            f"Error: The permit needs to have status '{required_status.name}' for this action to be performed.",
            status=400,
        )

    # Check user is on team for permit
    if not is_appointed_to(user, role_name, permit):
        return HttpResponse(
            f"Error: You're not listed on the team as {role_name} for this permit.",
            status=400,
        )

    # Check if a keep_loto_justification_comment was submitted
    if not request.POST.get("keep_loto_justification_comment"):
        return HttpResponse(
            f"Error: Must provide comment on why LOTO must stay in place.",
            status=400,
        )

    # Make entries in DB
    with transaction.atomic():
        # Add 'loto_must_stay' general confirmation
        confirmation_short_desc = "loto_must_stay"
        try:
            confm = Confirmation(
                confirmed=True,
                permit=permit,
                what=ConfirmationEvent.objects.get(
                    short_description=confirmation_short_desc
                ),
            )
            confm.save()
        except (ValidationError, IntegrityError):
            return HttpResponse(
                f"Failed to add '{confirmation_short_desc}' confirmation for permit #{permit.id}. All actions aborted. Please, contact admin.",
                status=400,
            )

        # Update permit status
        permit.status = PermitStatus.objects.get(id=13)
        permit.save()
        deactivate_inapplicable_action_notifs(permit)

        # Save the permit version
        contribution = Contribution(
            author=user,
            comment=request.POST.get("keep_loto_justification_comment").strip(),
            permit=permit,
            permit_total_content=get_full_permit_dict(permit),
        )
        contribution.save()

        # Create notifications for permit finalization
        for role in Role.objects.exclude(name="worker"):
            info_notif = InfoNotification(
                is_active=True,
                is_read=False,
                message=f"Permit #{permit.id} has been finalized. LOTO is still in place! (See keep_loto_justification_comment).",
                permit=permit,
                target_viewname="permitting:permit_display",
                user=permit.appointments.get(role=role).person,
            )
            info_notif.save()

        for entry in WorkerTeam.objects.filter(permit=permit):
            info_notif = InfoNotification(
                is_active=True,
                is_read=False,
                message=f"Permit #{permit.id} has been finalized. LOTO is still in place! (See keep_loto_justification_comment).",
                permit=permit,
                target_viewname="permitting:permit_display",
                user=entry.worker,
            )
            info_notif.save()

    # Redirect to view permit
    return HttpResponseRedirect(
        reverse("permitting:permit_display", kwargs={"permit_id": permit.id})
    )


@login_required
def redirect_to_action_view(request):
    """
    This route is used so that Action Notifications can have a button that leads to the page where an action must be performed.
    Basically, it receives the permit id and name of the target view as query parameters, and redirects to the target view,
    with the permit id as an argument.
    """
    if request.method != "GET":
        return HttpResponse(f"Error: GET request required", status=400)

    # Perform redirect
    return HttpResponseRedirect(
        reverse(
            request.GET.get("target_viewname"),
            kwargs={"permit_id": int(request.GET.get("permit_id"))},
        )
    )


@login_required
@csrf_exempt
def deactivate_info_notification(request):
    """
    Route to deactivate an Info Notification, making it no longer visible to the user.
    Returns a status message in JSON that can optionally be rendered.
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST request required."}, status=400)

    # Get info notification's id
    data = json.loads(request.body)

    try:
        info_notif_id = int(data.get("id").strip())
    except (ValueError, TypeError, IndexError):
        return JsonResponse({"error": "Invalid info notification id."}, status=403)

    # Check if such info notification exists
    try:
        info_notif = InfoNotification.objects.get(id=info_notif_id)
    except InfoNotification.DoesNotExist:
        return JsonResponse({"error": "Invalid info notification id."}, status=403)

    # Check user authorization
    if request.user != info_notif.user:
        return JsonResponse(
            {"error": "This info notification pertains to another user."}, status=403
        )

    # Flag info notification as inactive in DB
    try:
        info_notif.is_active = False
        info_notif.save()
    except (ValidationError, IntegrityError):
        return JsonResponse(
            {"error": "Failed to deactivate info notification."}, status=400
        )
    else:
        return JsonResponse({"message": "Success!"}, status=200)


@login_required
@csrf_exempt
def get_notifications_by_type_page(request):
    """
    Route that returns (JSON-serialized) paginated notifications of a specific type (info or action), and pertaining to a specific user.
    """
    def serialize_notifs(notifs):
        def serialize(notif):
            return {
                "created_on": notif.created_on,
                "id": notif.id,
                "message": notif.message,
                "permit_id": notif.permit.id,
                "target_viewname": notif.target_viewname,
            }

        if isinstance(notifs, Iterable) and not isinstance(notifs, str):
            return [serialize(notif) for notif in notifs]
        else:
            return serialize(notifs)


    if request.method != "GET":
        return JsonResponse({"error": "GET request required."}, status=400)

    # Determine selected notification type
    try:
        notif_type = request.GET.get("type")
    except (TypeError, ValueError):
        return JsonResponse(
            {"error": "Must provide notification type as query parameter."}, status=403
        )

    if not notif_type in ["action", "info"]:
        return JsonResponse(
            {"error": "Notification type must be either 'action' or 'info'."}, status=403
        )

    # Retrieve all notifications of selected type from DB
    user = request.user

    if notif_type == "action":
        notifs = user.action_notifications.filter(is_active=True)
    elif notif_type == "info":
        notifs = user.info_notifications.filter(is_active=True)

    # Sort descending
    notifs = sorted(
        notifs, key=lambda notif: notif.id, reverse=True
    )

    # Get number of page to be retrieved
    try:
        page_num = int(request.GET.get("page"))
    except (TypeError, ValueError):
        page_num = 1

    # Paginate
    p = Paginator(notifs, 3)
    page = p.page(page_num)

    return JsonResponse(
        {
            "current_page_num": page.number,
            "has_next": page.has_next(),
            "has_previous": page.has_previous(),
            "notifs": serialize_notifs(page.object_list),
        },
        safe=False,
    )


@login_required
@csrf_exempt
def get_permits_page(request):
    """
    Route that returns (JSON-serialized) paginated permits (acive or inactive), that are associated with a specific user.
    """
    def serialize_permits(permits):
        def serialize(permit):
            return {
                "area": permit.targeted_equipment.all()[0].area.name,
                "created_on": permit.created_on,
                "id": permit.id,
                "latest_change_on": permit.contributions.latest("created_on").created_on,
                "status": permit.status.name,
                "status_description": permit.status.short_description,
                "task_description": permit.task_description[:20],
            }

        if isinstance(permits, Iterable) and not isinstance(permits, str):
            return [serialize(permit) for permit in permits]
        else:
            return serialize(permits)


    if request.method != "GET":
        return JsonResponse({"error": "GET request required."}, status=400)

    # Determine if selected active permits
    raw_get_active = request.GET.get("get_active", "").strip().lower()

    if not raw_get_active in ["true", "false"]:
        return JsonResponse(
            {"error": "Must provide 'True' or 'False' as query parameter 'get_active'."}, status=403
        )
    else:
        get_active = raw_get_active == "true"


    # Retrieve permits from DB
    user = request.user
    permits_related_by_appointment = [item.permit for item in Appointment.objects.filter(person=user)]

    my_permits = set()

    if get_active :
        for p in permits_related_by_appointment:
            if not p.status.name in ["RJTD", "FINL", "CNLD"]:
                my_permits.add(p)
    else:
        for p in permits_related_by_appointment:
            if p.status.name in ["RJTD", "FINL", "CNLD"]:
                my_permits.add(p)

    if has_required_role(user, "worker"):
        wt_entries = user.in_workers_team.all()

        for entry in wt_entries:
            if get_active :
                if not entry.permit.status.name in ["RJTD", "FINL", "CNLD"]:
                    my_permits.add(entry.permit)
            else:
                if entry.permit.status.name in ["RJTD", "FINL", "CNLD"]:
                    my_permits.add(entry.permit)

    # Sort descending
    my_permits = sorted(
        my_permits, key=lambda permit: permit.id, reverse=True
    )

    # Get number of page to be retrieved
    try:
        page_num = int(request.GET.get("page"))
    except (TypeError, ValueError):
        page_num = 1

    # Paginate
    p = Paginator(my_permits, 3)
    page = p.page(page_num)

    return JsonResponse(
        {
            "current_page_num": page.number,
            "has_next": page.has_next(),
            "has_previous": page.has_previous(),
            "permits": serialize_permits(page.object_list),
        },
        safe=False,
    )


@login_required
@csrf_exempt
def risks_and_pps_by_eq(request):
    """
    Returns JSON-serialized lists of risks and personal protections, based on the area of the equipment, that is being worked on.
    """
    if request.method != "GET":
        return JsonResponse({"error": "GET request required."}, status=400)

    # Retrieve equipment from DB
    try:
        equipment = Equipment.objects.get(id=int(request.GET.get("equipment_id")))
    except (ValueError, Equipment.DoesNotExist):
        return JsonResponse(
            {"error": "No equipment with the stated id exists."}, status=400
        )
    else:
        if equipment.area is None:
            return JsonResponse(
                {
                    "error": "No area associated with stated equipment - can't fetch area-related data."
                },
                status=400,
            )

    risk_ids = [item.id for item in equipment.area.associated_risks.all()]
    personal_protection_ids = [
        item.id for item in equipment.area.required_personal_protection.all()
    ]

    # Return some JSON
    return JsonResponse(
        {
            "riskIds": risk_ids,
            "personalProtectionIds": personal_protection_ids,
        },
        safe=False,
    )
