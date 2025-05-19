from django.urls import path

from . import views

app_name = "permitting"

urlpatterns = [
    path("", views.index, name="index"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("my-permits", views.my_permits, name="my_permits"),
    path("notifications", views.notifications, name="notifications"),

    path("permit/issue-new", views.permit_issue_new, name="permit_issue_new"),
    path("permit/<int:permit_id>", views.permit_display, name="permit_display"),
    path("permit/<int:permit_id>/enter-staff", views.permit_enter_staff, name="permit_enter_staff"),
    path("permit/<int:permit_id>/authorize", views.permit_authorize, name="permit_authorize"),
    path("permit/<int:permit_id>/reject", views.permit_reject, name="permit_reject"),
    path("permit/<int:permit_id>/add-loto", views.permit_add_loto, name="permit_add_loto"),
    path("permit/<int:permit_id>/safety-gk", views.permit_safety_gk, name="permit_safety_gk"),
    path("permit/<int:permit_id>/task-instruction", views.permit_task_instruction, name="permit_task_instruction"),
    path("permit/<int:permit_id>/confirm-debriefing", views.permit_confirm_debriefing, name="permit_confirm_debriefing"),
    path("permit/<int:permit_id>/open-for-workday", views.permit_open_for_day, name="permit_open_for_day"),
    path("permit/<int:permit_id>/close-for-workday", views.permit_close_for_day, name="permit_close_for_day"),
    path("permit/<int:permit_id>/apply-for-finalization", views.permit_apply_for_finalization, name="permit_apply_for_finalization"),
    path("permit/<int:permit_id>/review-finalization-application", views.permit_review_finalization_application, name="permit_review_finalization_application"),
    path("permit/<int:permit_id>/refuse-finalization", views.permit_refuse_finalization, name="permit_refuse_finalization"),
    path("permit/<int:permit_id>/remove-loto", views.permit_remove_loto, name="permit_remove_loto"),
    path("permit/<int:permit_id>/finalize", views.permit_finalize, name="permit_finalize"),

    path("redirect-to-actionview", views.redirect_to_action_view, name="redirect_to_action_view"),

    # API Routes
    path("deactivate-info-notification", views.deactivate_info_notification, name="deactivate_info_notification"),
    path("get-notifications-by-type-page", views.get_notifications_by_type_page, name="get_notifications_by_type_page"),
    path("get-permits-page", views.get_permits_page, name="get_permits_page"),
    path("risks-and-pps-by-eq", views.risks_and_pps_by_eq, name="risks_and_pps_by_eq"),
]


