from django.test import Client, TestCase

from .helpers_general import appoint_for_duty, get_full_permit_dict
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


class TestCasesBase(TestCase):
    def setUp(self):
        """
        Provides the data foundation to do the testing on
        """
        # Create contractor orgs
        org1 = ContractorOrg.objects.create(
            name="123 Facility Solutions", number=3000000000
        )

        # Create roles
        issuer_role = Role.objects.create(name="issuer")
        task_responsible_role = Role.objects.create(name="task_responsible")
        authorizer_role = Role.objects.create(name="authorizer")
        loto_officer_role = Role.objects.create(name="loto_officer")
        safety_gatekeeper_role = Role.objects.create(name="safety_gatekeeper")
        foreman_role = Role.objects.create(name="foreman")
        worker_role = Role.objects.create(name="worker")

        # Create users
        issuer = User.objects.create_user(
            username="issuer", email="issuer@somemail.com", password="0000"
        )
        issuer.eligible_for_roles.add(issuer_role)
        issuer.save()

        authorizer = User.objects.create_user(
            username="authorizer", email="authorizer@somemail.com", password="0000"
        )
        authorizer.eligible_for_roles.add(authorizer_role)
        authorizer.save()

        loto_officer = User.objects.create_user(
            username="loto_officer", email="loto_officer@somemail.com", password="0000"
        )
        loto_officer.eligible_for_roles.add(loto_officer_role)
        loto_officer.save()

        safety_gatekeeper = User.objects.create_user(
            username="safety_gatekeeper",
            email="safety_gatekeeper@somemail.com",
            password="0000",
        )
        safety_gatekeeper.eligible_for_roles.add(safety_gatekeeper_role)
        safety_gatekeeper.save()

        task_responsible = User.objects.create_user(
            username="task_responsible",
            email="task_responsible@somemail.com",
            org=org1,
            password="0000",
        )
        task_responsible.eligible_for_roles.add(task_responsible_role)
        task_responsible.save()

        foreman = User.objects.create_user(
            username="foreman", email="foreman@somemail.com", org=org1, password="0000"
        )
        foreman.eligible_for_roles.add(foreman_role)
        foreman.save()

        w1 = User.objects.create_user(
            username="w1", email="w1@somemail.com", org=org1, password="0000"
        )
        w1.eligible_for_roles.add(worker_role)
        w1.save()

        w2 = User.objects.create_user(
            username="w2", email="w2@somemail.com", org=org1, password="0000"
        )
        w2.eligible_for_roles.add(worker_role)
        w2.save()

        w3 = User.objects.create_user(
            username="w3", email="w3@somemail.com", org=org1, password="0000"
        )
        w3.eligible_for_roles.add(worker_role)
        w3.save()

        # Create area-related risks
        r1 = AreaRelatedRisk.objects.create(description="pass", name="Dangerous Fluids")
        r2 = AreaRelatedRisk.objects.create(description="pass", name="Toxic Substances")
        r3 = AreaRelatedRisk.objects.create(description="pass", name="Height")
        r4 = AreaRelatedRisk.objects.create(description="pass", name="Electrical shock")
        r5 = AreaRelatedRisk.objects.create(description="pass", name="Confined spaces")
        r6 = AreaRelatedRisk.objects.create(description="pass", name="Excavation Works")
        r7 = AreaRelatedRisk.objects.create(description="pass", name="Load Handling")
        r8 = AreaRelatedRisk.objects.create(description="pass", name="Noise")
        r9 = AreaRelatedRisk.objects.create(description="pass", name="Traffic")

        # Create personal protections
        pp1 = PersonalProtection.objects.create(
            description="pass", name="Hearing protection"
        )
        pp2 = PersonalProtection.objects.create(
            description="pass", name="Safety Gloves"
        )
        pp3 = PersonalProtection.objects.create(description="pass", name="Dust Mask")
        pp4 = PersonalProtection.objects.create(description="pass", name="Gas Mask")
        pp5 = PersonalProtection.objects.create(description="pass", name="Gas Detector")
        pp6 = PersonalProtection.objects.create(
            description="pass", name="Eyesight Protection"
        )
        pp7 = PersonalProtection.objects.create(
            description="pass", name="Welding Screen"
        )
        pp8 = PersonalProtection.objects.create(description="pass", name="HazMat Suit")
        pp9 = PersonalProtection.objects.create(
            description="pass", name="Safety Harness"
        )
        pp10 = PersonalProtection.objects.create(
            description="pass", name="Reflective Vest"
        )

        # Create areas
        ar1 = Area.objects.create(name="Raw Material Handling & Storage")
        ar1.associated_risks.add(r1, r7, r9)
        ar1.required_personal_protection.add(pp2, pp10)
        ar1.save()

        ar2 = Area.objects.create(name="Polymerization")
        ar2.associated_risks.add(r1, r2)
        ar2.required_personal_protection.add(pp5, pp6)
        ar2.save()

        ar3 = Area.objects.create(name="Mixing & Compounding")
        ar3.associated_risks.add(r1, r2, r8)
        ar3.required_personal_protection.add(pp1, pp5, pp6)
        ar3.save()

        ar4 = Area.objects.create(name="Extrusion & Molding")
        ar4.associated_risks.add(r1, r2, r8)
        ar4.required_personal_protection.add(pp1, pp6)
        ar4.save()

        ar5 = Area.objects.create(name="Finishing & Packaging")
        ar5.associated_risks.add(r7, r8)
        ar5.required_personal_protection.add(pp1, pp6)
        ar5.save()

        ar6 = Area.objects.create(name="Utilities & Support Services")
        ar6.associated_risks.add(r1, r2, r4, r8)
        ar6.required_personal_protection.add(pp1, pp6)
        ar6.save()

        ar7 = Area.objects.create(name="Administrative")
        ar7.associated_risks.add(r9)
        ar7.required_personal_protection.add(pp10)
        ar7.save()

        # Create collective protections
        cp1 = CollectiveProtection.objects.create(
            description="pass", name="Fences & Warning Signs"
        )
        cp2 = CollectiveProtection.objects.create(
            description="pass", name="Scaffolding & Elevated Platforms"
        )
        cp3 = CollectiveProtection.objects.create(
            description="pass", name="Hazardous Gas Analyzer"
        )
        cp4 = CollectiveProtection.objects.create(
            description="pass", name="Safety Line"
        )
        cp5 = CollectiveProtection.objects.create(
            description="pass", name="Equipment with safe voltage"
        )
        cp6 = CollectiveProtection.objects.create(
            description="pass", name="Constant Ventilation"
        )

        # Create equipments
        eq1 = Equipment.objects.create(description="pass", tag="eq1-1", area=ar1)
        eq2 = Equipment.objects.create(description="pass", tag="eq2-1", area=ar1)
        eq3 = Equipment.objects.create(description="pass", tag="eq1-2", area=ar2)
        eq4 = Equipment.objects.create(description="pass", tag="eq2-2", area=ar2)
        eq5 = Equipment.objects.create(description="pass", tag="eq1-3", area=ar3)
        eq6 = Equipment.objects.create(description="pass", tag="eq2-3", area=ar3)
        eq7 = Equipment.objects.create(description="pass", tag="eq1-4", area=ar4)
        eq8 = Equipment.objects.create(description="pass", tag="eq2-4", area=ar4)
        eq9 = Equipment.objects.create(description="pass", tag="eq1-5", area=ar5)
        eq10 = Equipment.objects.create(description="pass", tag="eq2-5", area=ar5)
        eq11 = Equipment.objects.create(description="pass", tag="eq1-6", area=ar6)
        eq12 = Equipment.objects.create(description="pass", tag="eq2-6", area=ar6)
        eq13 = Equipment.objects.create(description="pass", tag="eq1-7", area=ar7)
        eq14 = Equipment.objects.create(description="pass", tag="eq2-7", area=ar7)

        # Create safety measures
        sm1 = SafetyMeasure.objects.create(description="pass", name="Lockout - Steam")
        sm2 = SafetyMeasure.objects.create(description="pass", name="Lockout - Water")
        sm3 = SafetyMeasure.objects.create(description="pass", name="Lockout - Gas")
        sm4 = SafetyMeasure.objects.create(
            description="pass", name="Lockout & tagout - electricity"
        )
        sm5 = SafetyMeasure.objects.create(
            description="pass", name="Lockout & tagout - control systems"
        )
        sm6 = SafetyMeasure.objects.create(
            description="pass", name="Doesn't require lockout & tagout"
        )

        # Create permit statuses
        pst1 = PermitStatus.objects.create(short_description="pass", name="INIT")
        pst2 = PermitStatus.objects.create(short_description="pass", name="STFF")
        pst3 = PermitStatus.objects.create(short_description="pass", name="AUTH")
        pst4 = PermitStatus.objects.create(short_description="pass", name="RJTD")
        pst5 = PermitStatus.objects.create(short_description="pass", name="LOTO")
        pst6 = PermitStatus.objects.create(short_description="pass", name="SFTG")
        pst7 = PermitStatus.objects.create(short_description="pass", name="TSPI")
        pst8 = PermitStatus.objects.create(short_description="pass", name="DEBR")
        pst9 = PermitStatus.objects.create(short_description="pass", name="DOPN")
        pst10 = PermitStatus.objects.create(short_description="pass", name="DCLS")
        pst11 = PermitStatus.objects.create(short_description="pass", name="APFN")
        pst12 = PermitStatus.objects.create(short_description="pass", name="RLTO")
        pst13 = PermitStatus.objects.create(short_description="pass", name="FINL")
        pst14 = PermitStatus.objects.create(short_description="pass", name="CNLD")
        pst15 = PermitStatus.objects.create(short_description="pass", name="MSTF")

        # Create confirmation events
        cfe1 = ConfirmationEvent.objects.create(short_description="initialization_ok")
        cfe2 = ConfirmationEvent.objects.create(short_description="loto_in_place")
        cfe3 = ConfirmationEvent.objects.create(
            short_description="performed_general_safety_briefing"
        )
        cfe4 = ConfirmationEvent.objects.create(
            short_description="performed_task_specific_briefing"
        )
        cfe5 = ConfirmationEvent.objects.create(short_description="task_completed")
        cfe6 = ConfirmationEvent.objects.create(short_description="workplace_cleaned")
        cfe7 = ConfirmationEvent.objects.create(short_description="eq_safe_to_operate")
        cfe8 = ConfirmationEvent.objects.create(
            short_description="allowed_loto_removal"
        )
        cfe9 = ConfirmationEvent.objects.create(short_description="loto_must_stay")
        cfe10 = ConfirmationEvent.objects.create(short_description="loto_removed")

    def assert_all_from_input_is_recorded_in_permit_entry(
        self, input_list, resulting_many_to_many
    ):
        temp = resulting_many_to_many.all()
        for i in range(0, temp.count()):
            self.assertEqual(temp[i].id, int(input_list[i]))

        return


class RouteIndexCases(TestCasesBase):
    def test_index_page(self):
        c = Client()
        response = c.get("/")
        self.assertEqual(response.status_code, 302)

        c.login(username="issuer", password="0000")
        response = c.get("/")
        self.assertEqual(response.status_code, 200)


class RoutePermitIssueNewCases(TestCasesBase):
    def test_authorization_check(self):
        c = Client()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get("/permit/issue-new")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get("/permit/issue-new")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="issuer", password="0000")
        resp = c.get("/permit/issue-new")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="issuer", password="0000")
        resp = c.get("/permit/issue-new")
        self.assertEqual(resp.status_code, 200)

        # Try POST with user_id for task_responsible that doesn't have the task_responsible role
        # (and, more broadly - tests behavior when passed ID out of select options range)
        resp = c.post(
            "/permit/issue-new",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "task_description": ["have to do some task"],
                "targeted_equipment": ["1"],
                "risks": ["1", "2", "3"],
                "personal_protection": ["1", "2", "3"],
                "collective_protection": ["1", "2", "3"],
                "safety_measures": ["1", "2", "3"],
                "task_responsible": ["1"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with no task description
        resp = c.post(
            "/permit/issue-new",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "task_description": [""],
                "targeted_equipment": ["1"],
                "risks": ["1", "2", "3"],
                "personal_protection": ["1", "2", "3"],
                "collective_protection": ["1", "2", "3"],
                "safety_measures": ["1", "2", "3"],
                "task_responsible": ["5"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        resp = c.post(
            "/permit/issue-new",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "targeted_equipment": ["1"],
                "risks": ["1", "2", "3"],
                "personal_protection": ["1", "2", "3"],
                "collective_protection": ["1", "2", "3"],
                "safety_measures": ["1", "2", "3"],
                "task_responsible": ["5"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="issuer", password="0000")
        resp = c.get("/permit/issue-new")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        count_permits_in_db = Permit.objects.all().count()
        count_appointments_in_db = Appointment.objects.all().count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            "/permit/issue-new",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "task_description": ["have to do some task"],
                "targeted_equipment": ["10"],
                "risks": ["1", "2", "3"],
                "personal_protection": ["1", "2", "3"],
                "collective_protection": ["1", "2", "3"],
                "safety_measures": ["1", "2", "3"],
                "task_responsible": ["5"],
                "comment": ["test"],
            },
        )
        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if permit added
        self.assertEqual(Permit.objects.all().count(), (count_permits_in_db + 1))

        # Check if appointments added
        self.assertEqual(
            Appointment.objects.all().count(), (count_appointments_in_db + 3)
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

        # Try POST with no (contribution) comment
        resp = c.post(
            "/permit/issue-new",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "task_description": ["have to do some task"],
                "targeted_equipment": ["1"],
                "risks": ["1", "2", "3"],
                "personal_protection": ["1", "2", "3"],
                "collective_protection": ["1", "2", "3"],
                "safety_measures": ["1", "2", "3"],
                "task_responsible": ["5"],
                "comment": [""],
            },
        )
        self.assertEqual(resp.status_code, 302)

    def test_db_entry_correctness(self):
        c = Client()

        # Log-in a user with the required role
        username = "issuer"
        c.login(username=username, password="0000")
        resp = c.get("/permit/issue-new")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        permit_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "task_description": ["have to do some task"],
            "targeted_equipment": ["1"],
            "risks": ["1", "2", "3"],
            "personal_protection": ["1", "2", "3"],
            "collective_protection": ["1", "2", "3"],
            "safety_measures": ["1", "2", "3"],
            "task_responsible": ["5"],
            "comment": ["test"],
        }

        resp = c.post("/permit/issue-new", permit_input)

        # Test each of resulting permit's fields == form's matching fields
        p = Permit.objects.latest("created_on")

        self.assertEqual(p.task_description, permit_input["task_description"][0])

        self.assert_all_from_input_is_recorded_in_permit_entry(
            permit_input["targeted_equipment"], p.targeted_equipment
        )
        self.assert_all_from_input_is_recorded_in_permit_entry(
            permit_input["risks"], p.risks
        )
        self.assert_all_from_input_is_recorded_in_permit_entry(
            permit_input["personal_protection"], p.personal_protection
        )
        self.assert_all_from_input_is_recorded_in_permit_entry(
            permit_input["collective_protection"], p.collective_protection
        )
        self.assert_all_from_input_is_recorded_in_permit_entry(
            permit_input["safety_measures"], p.safety_measures
        )

        # Test appropriate appointments added
        user = User.objects.get(username=username)
        self.assertTrue(
            p.appointments.filter(
                person=user,
                role=Role.objects.get(name="issuer"),
            ).exists()
        )

        self.assertTrue(
            p.appointments.filter(
                person=User.objects.get(id=int(permit_input["task_responsible"][0])),
                role=Role.objects.get(name="task_responsible"),
            ).exists()
        )

        self.assertTrue(
            p.appointments.filter(
                role=Role.objects.get(name="authorizer"),
            ).exists()
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, user)
        self.assertEqual(contrib.comment, permit_input["comment"][0])
        self.assertEqual(contrib.permit, p)
        # The below just tests whether the serialized permit is correctly recorded in the DB
        # The serialization function itself needs to be tested separately
        self.assertEqual(contrib.permit_total_content, get_full_permit_dict(p))

    def test_notifications(self):
        # Do POST
        c = Client()
        c.login(username="issuer", password="0000")
        c.post(
            "/permit/issue-new",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "task_description": ["have to do some task"],
                "targeted_equipment": ["10"],
                "risks": ["1", "2", "3"],
                "personal_protection": ["1", "2", "3"],
                "collective_protection": ["1", "2", "3"],
                "safety_measures": ["1", "2", "3"],
                "task_responsible": ["5"],
                "comment": ["test"],
            },
        )

        p = Permit.objects.latest("created_on")

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="task_responsible")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)
        self.assertTrue(action_notif.created_at_status == p.status)
        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_enter_staff")

class RoutePermitEnterStaffCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=1),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['task_responsible', 'authorizer', 'issuer']:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/enter-staff")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/enter-staff")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="task_responsible", password="0000")
        resp = c.get(f"/permit/{p.id}/enter-staff")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        c.login(username="task_responsible", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/enter-staff")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["6"],
                "workers": ["7", "8", "9"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with no user ids
        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "workers": [],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing id for user that doesn't have the 'foreman' role
        # (and, more broadly - tests behavior when passed ID out of select options range)
        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["1"],
                "workers": ["7", "8", "9"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST when foreman has a non-existing user id
        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["66"],
                "workers": ["7", "8", "9"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing ids for users that don't have the 'worker' role
        # (and, more broadly - tests behavior when passed ID out of select options range)
        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["6"],
                "workers": ["1", "2", "3"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST when one of the workers has a non-existing user id
        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["6"],
                "workers": ["7", "8", "999"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST when one of the workers is part of a worker team for another active permit
        p_conflicting = Permit(
            status=PermitStatus.objects.get(name="DOPN"),
            task_description="pass",
        )
        p_conflicting.save()

        wt = WorkerTeam(permit=p_conflicting, worker=User.objects.get(id=9))
        wt.save()

        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["6"],
                "workers": ["7", "8", "9"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/enter-staff")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["6"],
                "workers": ["7", "8", "9"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="task_responsible", password="0000")
        resp = c.get(f"/permit/{p.id}/enter-staff")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        count_appointments_in_db = Appointment.objects.filter(permit=p).count()
        count_workers_for_permit_in_db = WorkerTeam.objects.filter(permit=p).count()
        target_status = PermitStatus.objects.get(id=2)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["6"],
                "workers": ["7", "8", "9"],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if entries to worker teams added
        self.assertEqual(
            WorkerTeam.objects.filter(permit=p).count(),
            (count_workers_for_permit_in_db + 3),
        )

        # Check if appointments added
        self.assertEqual(
            Appointment.objects.filter(permit=p).count(), (count_appointments_in_db + 1)
        )

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "task_responsible"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "foreman": ["6"],
            "workers": ["7", "8", "9"],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/enter-staff", post_input)

        # Test each of DB field == form's matching fields
        for worker_user_id in post_input["workers"]:
            self.assertTrue(
                WorkerTeam.objects.filter(
                    permit=p,
                    worker=User.objects.get(id=int(worker_user_id)),
                ).exists()
            )

        # Test appropriate appointments added
        self.assertTrue(
            p.appointments.filter(
                person=User.objects.get(id=int(post_input["foreman"][0])),
                role=Role.objects.get(name="foreman"),
            ).exists()
        )

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=2)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="task_responsible", password="0000")
        c.post(
            f"/permit/{p.id}/enter-staff",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "foreman": ["6"],
                "workers": ["7", "8", "9"],
                "comment": ["test"],
            },
        )

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="authorizer")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_authorize")

        # Test info notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="issuer")
        ).person

        info_notif = notified_user.info_notifications.get(permit=p)
        self.assertTrue(info_notif)
        self.assertTrue(info_notif.is_active)
        self.assertFalse(info_notif.is_read)
        self.assertTrue(info_notif.target_viewname == "permitting:permit_display")

class RoutePermitAuthorizeCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=2),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['task_responsible', 'authorizer', 'issuer', 'foreman']:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/authorize")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/authorize")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")
        resp = c.get(f"/permit/{p.id}/authorize")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/authorize")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["3"],
                "safety_gatekeeper": ["4"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with no user ids
        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "safety_gatekeeper": [],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing id for user that doesn't have the correct role
        # (and, more broadly - tests behavior when passed ID out of select options range)
        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["1"],
                "safety_gatekeeper": ["2"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["1"],
                "safety_gatekeeper": ["4"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["3"],
                "safety_gatekeeper": ["1"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST when loto_officer/safety_gatekeeper has a non-existing user id
        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["999"],
                "safety_gatekeeper": ["4"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["3"],
                "safety_gatekeeper": ["999"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/authorize")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["3"],
                "safety_gatekeeper": ["4"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="authorizer", password="0000")
        resp = c.get(f"/permit/{p.id}/authorize")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        count_appointments_in_db = Appointment.objects.filter(permit=p).count()
        target_status = PermitStatus.objects.get(id=3)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["3"],
                "safety_gatekeeper": ["4"],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        self.assertTrue(
            Confirmation.objects.filter(
                confirmed=True,
                permit=p,
                what=ConfirmationEvent.objects.get(
                    short_description="initialization_ok"
                ),
            ).exists()
        )

        # Check if appointments added
        self.assertEqual(
            Appointment.objects.filter(permit=p).count(), (count_appointments_in_db + 2)
        )

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "authorizer"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "loto_officer": ["3"],
            "safety_gatekeeper": ["4"],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/authorize", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Test appropriate appointments added
        self.assertTrue(
            p.appointments.filter(
                person=User.objects.get(id=int(post_input["loto_officer"][0])),
                role=Role.objects.get(name="loto_officer"),
            ).exists()
        )

        self.assertTrue(
            p.appointments.filter(
                person=User.objects.get(id=int(post_input["safety_gatekeeper"][0])),
                role=Role.objects.get(name="safety_gatekeeper"),
            ).exists()
        )

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=3)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="authorizer", password="0000")
        c.post(
            f"/permit/{p.id}/authorize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "loto_officer": ["3"],
                "safety_gatekeeper": ["4"],
                "comment": ["test"],
            },
        )

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="loto_officer")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_add_loto")

        # Test info notifications
        for role_name in ["issuer", "task_responsible", "foreman", "safety_gatekeeper"]:
            notified_user = p.appointments.get(
                    role=Role.objects.get(name=role_name)
            ).person

            info_notif = notified_user.info_notifications.get(permit=p)
            self.assertTrue(info_notif)
            self.assertTrue(info_notif.is_active)
            self.assertFalse(info_notif.is_read)
            self.assertTrue(info_notif.target_viewname == "permitting:permit_display")

class RoutePermitRejectCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=2),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['task_responsible', 'authorizer', 'issuer']:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/reject")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role, and try GET (the route should only accept POST)
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/reject")
        self.assertEqual(resp.status_code, 400)

        # Log-in a user with the required role, and try GET (the route should only accept POST)
        c.login(username="w1", password="0000")
        c.login(username="authorizer", password="0000")
        resp = c.get(f"/permit/{p.id}/reject")
        self.assertEqual(resp.status_code, 400)

    def test_handle_bad_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/reject")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/reject",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "rejection_comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with no rejection_comment
        resp = c.post(
            f"/permit/{p.id}/reject",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
            },
        )
        self.assertEqual(resp.status_code, 400)

        resp = c.post(
            f"/permit/{p.id}/reject",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "rejection_comment": [""],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.post(
            f"/permit/{p.id}/reject",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "rejection_comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=4)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/reject",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "rejection_comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "authorizer"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "rejection_comment": ["test"],
        }

        c.post(f"/permit/{p.id}/reject", post_input)

        # Test each of DB field == form's matching fields

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=4)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="authorizer", password="0000")
        c.post(
            f"/permit/{p.id}/reject",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "rejection_comment": ["test"],
            },
        )

        # Test info notifications
        for role_name in ["issuer", "task_responsible"]:
            notified_user = p.appointments.get(
                    role=Role.objects.get(name=role_name)
            ).person

            info_notif = notified_user.info_notifications.get(permit=p)
            self.assertTrue(info_notif)
            self.assertTrue(info_notif.is_active)
            self.assertFalse(info_notif.is_read)
            self.assertTrue(info_notif.target_viewname == "permitting:permit_display")

class RoutePermitAddLotoCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=3),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['loto_officer', 'safety_gatekeeper']:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/add-loto")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/add-loto")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="loto_officer", password="0000")
        resp = c.get(f"/permit/{p.id}/add-loto")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="loto_officer", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/add-loto")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/add-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing()
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/add-loto")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/add-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="loto_officer", password="0000")
        resp = c.get(f"/permit/{p.id}/add-loto")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=5)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/add-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        self.assertTrue(
            Confirmation.objects.filter(
                confirmed=True,
                permit=p,
                what=ConfirmationEvent.objects.get(
                    short_description="loto_in_place"
                ),
            ).exists()
        )

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "loto_officer"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/add-loto", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=5)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="loto_officer", password="0000")
        c.post(
            f"/permit/{p.id}/add-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_safety_gk")

class RoutePermitSafetyGkCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=5),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['safety_gatekeeper', 'task_responsible']:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/safety-gk")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/safety-gk")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/safety-gk")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="safety_gatekeeper", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/safety-gk")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/safety-gk",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing()
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/safety-gk")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/safety-gk",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/safety-gk")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=6)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/safety-gk",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        self.assertTrue(
            Confirmation.objects.filter(
                confirmed=True,
                permit=p,
                what=ConfirmationEvent.objects.get(
                    short_description="performed_general_safety_briefing"
                ),
            ).exists()
        )

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "safety_gatekeeper"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/safety-gk", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=6)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="safety_gatekeeper", password="0000")
        c.post(
            f"/permit/{p.id}/safety-gk",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="task_responsible")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_task_instruction")

class RoutePermitTaskInstructionCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=6),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint person for the possition of 'task_responsible'
        a = Appointment(
            permit=p,
            person=User.objects.get(username="task_responsible"),
            role=Role.objects.get(name="task_responsible"),
        )
        a.save()

        # Add workers
        some_worker_usernames = ["w1", "w3"]

        for username in some_worker_usernames:
            person = User.objects.get(username=username)
            wt = WorkerTeam(permit=p, worker=person)

            wt.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/task-instruction")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/task-instruction")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="task_responsible", password="0000")
        resp = c.get(f"/permit/{p.id}/task-instruction")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="task_responsible", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/task-instruction")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/task-instruction",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing()
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/task-instruction")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/task-instruction",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="task_responsible", password="0000")
        resp = c.get(f"/permit/{p.id}/task-instruction")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=7)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/task-instruction",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        self.assertTrue(
            Confirmation.objects.filter(
                confirmed=True,
                permit=p,
                what=ConfirmationEvent.objects.get(
                    short_description="performed_task_specific_briefing"
                ),
            ).exists()
        )

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "task_responsible"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/task-instruction", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=7)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="task_responsible", password="0000")
        c.post(
            f"/permit/{p.id}/task-instruction",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test action notifications
        for entry in WorkerTeam.objects.filter(permit=p):
            notified_user = entry.worker

            action_notif = notified_user.action_notifications.get(permit=p)
            self.assertTrue(action_notif)

            p = Permit.objects.get(id=p.id)
            self.assertTrue(action_notif.created_at_status == p.status)

            self.assertTrue(action_notif.is_active)
            self.assertFalse(action_notif.is_read)
            self.assertTrue(action_notif.target_viewname == "permitting:permit_confirm_debriefing")

class RoutePermitConfirmDebriefingCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=7),
            task_description="test",
        )
        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        some_worker_usernames = ["w1", "w3"]

        for username in some_worker_usernames:
            person = User.objects.get(username=username)
            wt = WorkerTeam(permit=p, worker=person)

            wt.save()

        # Appoint person for the possition of 'safety_gatekeeper'
        a = Appointment(
            permit=p,
            person=User.objects.get(username="safety_gatekeeper"),
            role=Role.objects.get(name="safety_gatekeeper"),
        )
        a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/confirm-debriefing")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="loto_officer", password="0000")
        resp = c.get(f"/permit/{p.id}/confirm-debriefing")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/confirm-debriefing")
        self.assertEqual(resp.status_code, 200)

        # Log-in a user with the required role, but not on team for this permit
        c.login(username="w2", password="0000")
        resp = c.get(f"/permit/{p.id}/confirm-debriefing")
        self.assertEqual(resp.status_code, 400)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="w1", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/confirm-debriefing")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/confirm-debriefing",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing()
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/confirm-debriefing")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/confirm-debriefing",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit, but with user who has already confirmed
        # Mock the confirmation
        p = self.get_permit_for_testing()
        wt_member = WorkerTeam.objects.get(permit=p, worker=User.objects.get(username="w3"))
        wt_member.debriefed_general = True
        wt_member.debriefed_specifics = True
        wt_member.save()

        c.login(username="w3", password="0000")
        resp = c.get(f"/permit/{p.id}/confirm-debriefing")
        self.assertEqual(resp.status_code, 403)

        # Try POST with existing permit, but with user who has already confirmed
        resp = c.post(
            f"/permit/{p.id}/confirm-debriefing",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 403)

    def test_handle_good_form(self):
        def check_post_method(self, client, permit, status_change_anticipated):
            """
            Does a POST for one of the multiple users that need to confirm
            """
            current_status = PermitStatus.objects.get(id=p.status.id)
            target_status = PermitStatus.objects.get(id=8)
            count_target_status_permits_in_db = Permit.objects.filter(
                status=target_status
            ).count()
            count_contributions_in_db = Contribution.objects.all().count()

            resp = client.post(
                f"/permit/{permit.id}/confirm-debriefing",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

            # Testing for code 302, because on success there will be a redirect to either single permit page or index
            self.assertEqual(resp.status_code, 302)


            # Check permit status
            if status_change_anticipated:
                self.assertEqual(
                    Permit.objects.filter(status=target_status).count(),
                    (count_target_status_permits_in_db + 1),
                )
            else:
                self.assertEqual(p.status, current_status)

            # Check if contribution added
            self.assertEqual(
                Contribution.objects.all().count(), (count_contributions_in_db + 1)
            )

            return

        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/confirm-debriefing")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form for user1 of 2 that need to confirm
        # Testing for no change of status, because another user is to confirm
        check_post_method(self, c, p, False)

        # Try POST with valid form for user2 of 2 that need to confirm
        # Now, anticipating the status should change
        c.login(username="w3", password="0000")
        check_post_method(self, c, p, True)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()
        c = Client()

        for entry in WorkerTeam.objects.filter(permit=p):
            c.login(username=entry.worker.username, password="0000")

            c.post(
                f"/permit/{p.id}/confirm-debriefing",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_open_for_day")

class RoutePermitOpenForDayCases(TestCasesBase):
    def get_permit_for_testing(self, required_status_num):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=int(required_status_num)),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        role_and_user_names = ["foreman", "safety_gatekeeper"]

        for item in role_and_user_names:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=item),
                role=Role.objects.get(name=item),
            )
            a.save()

        # Create mock notification to later test deactivation
        action_notif = ActionNotification(
            created_at_status=p.status,
            is_active=True,
            is_read=False,
            message=f"You're requested to confirm that workers may be allowed to the workplace for permit #{p.id}.",
            permit=p,
            target_viewname="permitting:permit_open_for_day",
            user=p.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
            ).person,
        )
        action_notif.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing(8)

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/open-for-workday")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/open-for-workday")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="foreman", password="0000")
        resp = c.get(f"/permit/{p.id}/open-for-workday")
        self.assertEqual(resp.status_code, 200)

        # Log-in a user with the required role
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/open-for-workday")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        # Log-in a user with the required role
        c = Client()
        c.login(username="foreman", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/open-for-workday")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/open-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing(8)
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/open-for-workday")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/open-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST as 'foreman' when 'safety_gatekeeper' is yet to confirm
        p = self.get_permit_for_testing(8)
        resp = c.post(
            f"/permit/{p.id}/open-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 403)

        # Try POST when 'safety_gatekeeper' has already confirmed
        p = self.get_permit_for_testing(8)

        oc_entry = DailyOpenClose(permit=p)
        oc_entry.save()

        oc_entry.confirmed_loto_in_place = True
        oc_entry.save()

        c.login(username="safety_gatekeeper", password="0000")

        resp = c.post(
            f"/permit/{p.id}/open-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 403)

        # Try POST when 'foreman' has already confirmed
        p = self.get_permit_for_testing(8)

        oc_entry = DailyOpenClose(permit=p)
        oc_entry.save()

        oc_entry.confirmed_led_workers_in = True
        oc_entry.save()

        c.login(username="foreman", password="0000")

        resp = c.post(
            f"/permit/{p.id}/open-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 403)

    def test_handle_good_form_for_role1(self):
        def check_post_method(self, p):
            """
            Does a POST for one of the two acceptable statuses
            """
            # Log-in a user with the required role & test GET method
            c = Client()
            c.login(username="safety_gatekeeper", password="0000")
            resp = c.get(f"/permit/{p.id}/open-for-workday")
            self.assertEqual(resp.status_code, 200)

            # Try POST with valid form
            target_status = PermitStatus.objects.get(id=9)
            count_target_status_permits_in_db = Permit.objects.filter(
                status=target_status
            ).count()
            count_contributions_in_db = Contribution.objects.all().count()

            resp = c.post(
                f"/permit/{p.id}/open-for-workday",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

            # Testing for code 302, because on success there will be a redirect to either single permit page or index
            self.assertEqual(resp.status_code, 302)

            # Check if appropriate confirmation created
            oc_entry = DailyOpenClose.objects.filter(
                permit=p, opened_at=None, closed_at=None
            ).latest("id")

            self.assertTrue(oc_entry.confirmed_loto_in_place)

            # Check permit status (shouldn't be updated yet!)
            self.assertEqual(
                Permit.objects.filter(status=target_status).count(),
                count_target_status_permits_in_db,
            )

            # Check if contribution added
            self.assertEqual(
                Contribution.objects.all().count(), (count_contributions_in_db + 1)
            )

            return

        # Check POST for each of the acceptable permit statuses
        acceptable_status_numbers = [8, 10]
        for n in acceptable_status_numbers:
            p = self.get_permit_for_testing(n)
            check_post_method(self, p)

    def test_handle_good_form_for_role2(self):
        def check_post_method(self, p):
            """
            Does a POST for one of the two acceptable statuses
            """
            # Mock the necessary prior confirmation
            oc_entry = DailyOpenClose(permit=p)
            oc_entry.save()

            oc_entry.confirmed_loto_in_place = True
            oc_entry.save()

            # Log-in a user with the required role & test GET method
            c = Client()
            c.login(username="foreman", password="0000")
            resp = c.get(f"/permit/{p.id}/open-for-workday")
            self.assertEqual(resp.status_code, 200)

            # Try POST with valid form
            target_status = PermitStatus.objects.get(id=9)
            count_target_status_permits_in_db = Permit.objects.filter(
                status=target_status
            ).count()
            count_contributions_in_db = Contribution.objects.all().count()

            resp = c.post(
                f"/permit/{p.id}/open-for-workday",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

            # Testing for code 302, because on success there will be a redirect to either single permit page or index
            self.assertEqual(resp.status_code, 302)

            # Check if appropriate confirmation created (need to re-capture oc_entry first!!!)
            oc_entry = DailyOpenClose.objects.filter(
                permit=p, closed_at=None
            ).latest("id")
            self.assertTrue(oc_entry.confirmed_led_workers_in)
            self.assertTrue(oc_entry.opened_at)

            # Check permit status
            self.assertEqual(
                Permit.objects.filter(status=target_status).count(),
                (count_target_status_permits_in_db + 1),
            )

            # Check if contribution added
            self.assertEqual(
                Contribution.objects.all().count(), (count_contributions_in_db + 1)
            )

        # Check POST for each of the acceptable permit statuses
        acceptable_status_numbers = [8, 10]
        for n in acceptable_status_numbers:
            p = self.get_permit_for_testing(n)
            check_post_method(self, p)

    def test_db_entry_correctness_role1(self):
        def check_post_method(self, p):
            """
            Does a POST for one of the two acceptable statuses
            """
            # Log-in a user with the required role & test GET method
            c = Client()
            c.login(username="safety_gatekeeper", password="0000")
            resp = c.get(f"/permit/{p.id}/open-for-workday")
            self.assertEqual(resp.status_code, 200)

            # Try POST with valid form
            current_status = PermitStatus.objects.get(id=p.status.id)
            resp = c.post(
                f"/permit/{p.id}/open-for-workday",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

            # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
            self.assertEqual(
                Permit.objects.get(id=p.id).status, current_status
            )

            # Check new contribution
            contrib = Contribution.objects.latest("created_on")

            self.assertEqual(contrib.author, User.objects.get(username="safety_gatekeeper"))
            self.assertEqual(contrib.permit, p)

            return

        # Check POST for each of the acceptable permit statuses
        acceptable_status_numbers = [8, 10]
        for n in acceptable_status_numbers:
            p = self.get_permit_for_testing(n)
            check_post_method(self, p)

    def test_db_entry_correctness_role2(self):
        def check_post_method(self, p):
            """
            Does a POST for one of the two acceptable statuses
            """
            # Mock the necessary prior confirmation
            oc_entry = DailyOpenClose(permit=p)
            oc_entry.save()

            oc_entry.confirmed_loto_in_place = True
            oc_entry.save()

            # Log-in a user with the required role & test GET method
            c = Client()
            c.login(username="foreman", password="0000")
            resp = c.get(f"/permit/{p.id}/open-for-workday")
            self.assertEqual(resp.status_code, 200)

            # Try POST with valid form
            resp = c.post(
                f"/permit/{p.id}/open-for-workday",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

            # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
            self.assertEqual(
                Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=9)
            )

            # Check new contribution
            contrib = Contribution.objects.latest("created_on")

            self.assertEqual(contrib.author, User.objects.get(username="foreman"))
            self.assertEqual(contrib.permit, p)

            return

        # Check POST for each of the acceptable permit statuses
        acceptable_status_numbers = [8, 10]
        for n in acceptable_status_numbers:
            p = self.get_permit_for_testing(n)
            check_post_method(self, p)

    def test_notifications_after_role1_does_post(self):
        acceptable_status_numbers = [8, 10]
        for n in acceptable_status_numbers:
            p = self.get_permit_for_testing(n)

            # Do POST
            c = Client()
            c.login(username="safety_gatekeeper", password="0000")
            c.post(
                f"/permit/{p.id}/open-for-workday",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

            # Test deactivated action notification
            notified_user = p.appointments.get(
                    role=Role.objects.get(name="safety_gatekeeper")
            ).person

            action_notif = notified_user.action_notifications.get(permit=p)
            self.assertTrue(action_notif)

            p = Permit.objects.get(id=p.id)
            self.assertTrue(action_notif.created_at_status == p.status)

            self.assertFalse(action_notif.is_active)
            self.assertTrue(action_notif.target_viewname == "permitting:permit_open_for_day")

            # Test action notification
            notified_user = p.appointments.get(
                    role=Role.objects.get(name="foreman")
            ).person

            action_notif = notified_user.action_notifications.get(permit=p)
            self.assertTrue(action_notif)

            p = Permit.objects.get(id=p.id)
            self.assertTrue(action_notif.created_at_status == p.status)

            self.assertTrue(action_notif.is_active)
            self.assertFalse(action_notif.is_read)
            self.assertTrue(action_notif.target_viewname == "permitting:permit_open_for_day")

    def test_notifications_after_role2_does_post(self):
        acceptable_status_numbers = [8, 10]
        for n in acceptable_status_numbers:
            p = self.get_permit_for_testing(n)

            # Mock the necessary prior confirmation
            oc_entry = DailyOpenClose(permit=p)
            oc_entry.save()

            oc_entry.confirmed_loto_in_place = True
            oc_entry.save()

            # Do POST
            c = Client()
            c.login(username="foreman", password="0000")
            c.post(
                f"/permit/{p.id}/open-for-workday",
                {
                    "csrfmiddlewaretoken": [
                        "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                    ],
                    "comment": ["test"],
                },
            )

            # Test action notification
            notified_user = p.appointments.get(
                    role=Role.objects.get(name="foreman")
            ).person

            action_notif = notified_user.action_notifications.get(permit=p)
            self.assertTrue(action_notif)

            p = Permit.objects.get(id=p.id)
            self.assertTrue(action_notif.created_at_status == p.status)

            self.assertTrue(action_notif.is_active)
            self.assertFalse(action_notif.is_read)
            self.assertTrue(action_notif.target_viewname == "permitting:permit_close_for_day")

class RoutePermitCloseForDayCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=9),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Create Open/Close entry
        oc_entry = DailyOpenClose(permit=p)
        oc_entry.save()

        # Appoint
        role_and_user_names = ["foreman", "safety_gatekeeper", "task_responsible"]

        for item in role_and_user_names:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=item),
                role=Role.objects.get(name=item),
            )
            a.save()

        # Create mock notification to later test deactivation
        action_notif = ActionNotification(
            created_at_status=p.status,
            is_active=True,
            is_read=False,
            message="test",
            permit=p,
            target_viewname="permitting:permit_close_for_day",
            user=p.appointments.get(
                role=Role.objects.get(name="foreman")
            ).person,
        )
        action_notif.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="foreman", password="0000")
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 200)

        # Mock foreman's confirmation
        oc_entry = DailyOpenClose.objects.filter(
            permit=p, closed_at=None
        ).latest("id")
        oc_entry.confirmed_led_workers_out = True
        oc_entry.save()

        # Log-in a user with the required role
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        # Log-in a user with the required role
        c = Client()
        c.login(username="foreman", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/close-for-workday")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing()
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST as 'safety_gatekeeper' when 'foreman' is yet to confirm
        p = self.get_permit_for_testing()
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 403)


        # Try POST as 'foreman' when 'foreman' has already confirmed
        p = self.get_permit_for_testing()

        oc_entry = DailyOpenClose(permit=p)
        oc_entry.save()

        oc_entry.confirmed_led_workers_out = True
        oc_entry.save()

        c.login(username="foreman", password="0000")

        resp = c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 403)

    def test_handle_good_form_for_role1(self):
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c = Client()
        c.login(username="foreman", password="0000")
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=10)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        oc_entry = DailyOpenClose.objects.filter(
            permit=p, opened_at=None, closed_at=None
        ).latest("id")

        self.assertTrue(oc_entry.confirmed_led_workers_out)

        # Check permit status (shouldn't be updated yet!)
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            count_target_status_permits_in_db,
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_handle_good_form_for_role2(self):
        p = self.get_permit_for_testing()

        # Mock the necessary prior confirmation
        oc_entry = DailyOpenClose(permit=p)
        oc_entry.save()

        oc_entry.confirmed_led_workers_out = True
        oc_entry.save()

        # Log-in a user with the required role & test GET method
        c = Client()
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=10)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created (need to re-capture oc_entry first!!!)
        oc_entry = DailyOpenClose.objects.filter( permit=p,).latest("id")
        self.assertTrue(oc_entry.closed_at)

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness_role1(self):
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c = Client()
        c.login(username="foreman", password="0000")
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        current_status = PermitStatus.objects.get(id=p.status.id)
        resp = c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, current_status
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username="foreman"))
        self.assertEqual(contrib.permit, p)

    def test_db_entry_correctness_role2(self):
        p = self.get_permit_for_testing()

        # Mock the necessary prior confirmation
        oc_entry = DailyOpenClose(permit=p)
        oc_entry.save()

        oc_entry.confirmed_led_workers_out = True
        oc_entry.save()

        # Log-in a user with the required role & test GET method
        c = Client()
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/close-for-workday")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        resp = c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=10)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username="safety_gatekeeper"))
        self.assertEqual(contrib.permit, p)

    def test_notifications_after_role1_does_post(self):
        p = self.get_permit_for_testing()

        # Do POST
        c = Client()
        c.login(username="foreman", password="0000")
        c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test deactivated action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="foreman")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertFalse(action_notif.is_active)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_close_for_day")

        # Test action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_close_for_day")

    def test_notifications_after_role2_does_post(self):
        p = self.get_permit_for_testing()

        # Mock the necessary prior confirmation
        oc_entry = DailyOpenClose(permit=p)
        oc_entry.save()

        oc_entry.confirmed_led_workers_out = True
        oc_entry.save()

        # Do POST
        c = Client()
        c.login(username="safety_gatekeeper", password="0000")
        c.post(
            f"/permit/{p.id}/close-for-workday",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_open_for_day")

        # Test action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="task_responsible")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_apply_for_finalization")

class RoutePermitApplyForFinalizationCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=10),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['task_responsible', 'authorizer']:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/apply-for-finalization")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/apply-for-finalization")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="task_responsible", password="0000")
        resp = c.get(f"/permit/{p.id}/apply-for-finalization")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        c.login(username="task_responsible", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/apply-for-finalization")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/apply-for-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "performed_tests_and_golive_procedures_description": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST without tests & go-live comment
        resp = c.post(
            f"/permit/{p.id}/apply-for-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "performed_tests_and_golive_procedures_description": [""],
            },
        )
        self.assertEqual(resp.status_code, 400)

        resp = c.post(
            f"/permit/{p.id}/apply-for-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "performed_tests_and_golive_procedures_description": [],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/apply-for-finalization")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/apply-for-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "performed_tests_and_golive_procedures_description": ["test"],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="task_responsible", password="0000")
        resp = c.get(f"/permit/{p.id}/apply-for-finalization")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=11)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/apply-for-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "performed_tests_and_golive_procedures_description": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmations created
        confirmation_short_descriptions = [
                    "task_completed",
                    "workplace_cleaned",
                    "eq_safe_to_operate",
                ]

        for confirmation_short_desc in confirmation_short_descriptions:
            self.assertTrue(
                Confirmation.objects.filter(
                    confirmed=True,
                    permit=p,
                    what=ConfirmationEvent.objects.get(
                        short_description=confirmation_short_desc
                    ),
                ).exists()
            )

        # Check tech completion time record exists (first need to re-fetch permit)
        p = Permit.objects.get(id=p.id)
        self.assertTrue(p.tech_completion_time)

        # Check tests & go-live comment recorded
        self.assertTrue(p.tests_and_golive_comment)

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "task_responsible"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
            "performed_tests_and_golive_procedures_description": ["test"],
        }

        c.post(f"/permit/{p.id}/apply-for-finalization", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=11)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="task_responsible", password="0000")
        c.post(
            f"/permit/{p.id}/apply-for-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "performed_tests_and_golive_procedures_description": ["test"],
            },
        )

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="authorizer")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_review_finalization_application")

class RoutePermitReviewFinalizationApplicationCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=11),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['task_responsible', 'authorizer', 'loto_officer']:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/review-finalization-application")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/review-finalization-application")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")
        resp = c.get(f"/permit/{p.id}/review-finalization-application")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/review-finalization-application")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/review-finalization-application",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing()
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/review-finalization-application")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/review-finalization-application",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)


    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="authorizer", password="0000")
        resp = c.get(f"/permit/{p.id}/review-finalization-application")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=12)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/review-finalization-application",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        self.assertTrue(
            Confirmation.objects.filter(
                confirmed=True,
                permit=p,
                what=ConfirmationEvent.objects.get(
                    short_description="allowed_loto_removal"
                ),
            ).exists()
        )

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "authorizer"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/review-finalization-application", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=12)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="authorizer", password="0000")
        c.post(
            f"/permit/{p.id}/review-finalization-application",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test action notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="loto_officer")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_remove_loto")

        # Test info notifications
        notified_user = p.appointments.get(
                role=Role.objects.get(name="task_responsible")
        ).person

        info_notif = notified_user.info_notifications.get(permit=p)
        self.assertTrue(info_notif)
        self.assertTrue(info_notif.is_active)
        self.assertFalse(info_notif.is_read)
        self.assertTrue(info_notif.target_viewname == "permitting:permit_display")

class RoutePermitRefuseFinalizationCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=11),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for username in ['task_responsible', 'authorizer', "safety_gatekeeper"]:
            a = Appointment(
                permit=p,
                person=User.objects.get(username=username),
                role=Role.objects.get(name=username),
            )
            a.save()

        # Create mock notification to later test deactivation
        action_notif = ActionNotification(
            created_at_status=p.status,
            is_active=True,
            is_read=False,
            message="test",
            permit=p,
            target_viewname="permitting:permit_review_finalization_application",
            user=p.appointments.get(
                role=Role.objects.get(name="authorizer")
            ).person,
        )
        action_notif.save()

        return p

    def test_authorization_check(self):
        c = Client()
        p = self.get_permit_for_testing()

        # (!) This route should accept only POST requests and return 400 in all other cases, regardless of user
        # Try GET without logged-in user - this is the exception: for not logged-in users, there is a redirect
        # beacuse of `@login_required`
        resp = c.get(f"/permit/{p.id}/refuse-finalization")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/refuse-finalization")
        self.assertEqual(resp.status_code, 400)

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")
        resp = c.get(f"/permit/{p.id}/refuse-finalization")
        self.assertEqual(resp.status_code, 400)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/refuse-finalization")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/refuse-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "refuse_finalization_comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit but without `refuse_finalization_comment`
        p = self.get_permit_for_testing()
        resp = c.post(
            f"/permit/{p.id}/refuse-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.post(
            f"/permit/{p.id}/refuse-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "refuse_finalization_comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=10)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/refuse-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "refuse_finalization_comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmations created
        confirmation_short_descriptions = [
                    "task_completed",
                    "workplace_cleaned",
                    "eq_safe_to_operate",
                ]

        for confirmation_short_desc in confirmation_short_descriptions:
            try:
                confm = Confirmation.objects.get(
                    permit=p,
                    what=ConfirmationEvent.objects.get(
                        short_description=confirmation_short_desc
                    ),
                )
            except Confirmation.DoesNotExist:
                pass
            else:
                self.assertFalse(confm.confirmed)

        # Check tech completion time record exists (first need to re-fetch permit)
        p = Permit.objects.get(id=p.id)
        self.assertTrue(p.tech_completion_time == None)

        # Check tests & go-live comment recorded
        self.assertTrue(p.tests_and_golive_comment == "")

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "authorizer"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
            "refuse_finalization_comment": ["test"],
        }

        c.post(f"/permit/{p.id}/refuse-finalization", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=10)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        p = self.get_permit_for_testing()

        # Do POST
        c = Client()
        c.login(username="authorizer", password="0000")
        c.post(
            f"/permit/{p.id}/refuse-finalization",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "refuse_finalization_comment": ["test"],
            },
        )

        # Test deactivated action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="authorizer")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)
        self.assertFalse(action_notif.is_active)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_review_finalization_application")

        # Test action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="task_responsible")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_apply_for_finalization")

        # Test action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_open_for_day")

class RoutePermitFinalizeCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=11),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for role in Role.objects.exclude(name="worker"):
            a = Appointment(
                permit=p,
                person=User.objects.get(username=role.name),
                role=Role.objects.get(name=role.name),
            )
            a.save()

        # Appoint
        some_worker_usernames = ["w1", "w3"]

        for username in some_worker_usernames:
            person = User.objects.get(username=username)
            wt = WorkerTeam(permit=p, worker=person)

            wt.save()

        return p

    def test_authorization_check(self):
        c = Client()
        p = self.get_permit_for_testing()

        # (!) This route should accept only POST requests and return 400 in all other cases, regardless of user
        # Try GET without logged-in user - this is the exception: for not logged-in users, there is a redirect
        # beacuse of `@login_required`
        resp = c.get(f"/permit/{p.id}/finalize")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/finalize")
        self.assertEqual(resp.status_code, 400)

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")
        resp = c.get(f"/permit/{p.id}/finalize")
        self.assertEqual(resp.status_code, 400)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/finalize")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/finalize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "keep_loto_justification_comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit but without `keep_loto_justification_comment`
        p = self.get_permit_for_testing()
        resp = c.post(
            f"/permit/{p.id}/finalize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.post(
            f"/permit/{p.id}/finalize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "keep_loto_justification_comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_handle_good_form(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        c.login(username="authorizer", password="0000")

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=13)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/finalize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "keep_loto_justification_comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        self.assertTrue(
            Confirmation.objects.filter(
                confirmed=True,
                permit=p,
                what=ConfirmationEvent.objects.get(
                    short_description="loto_must_stay"
                ),
            ).exists()
        )

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "authorizer"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
            "keep_loto_justification_comment": ["test"],
        }

        c.post(f"/permit/{p.id}/finalize", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=13)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications(self):
        # Do POST
        p = self.get_permit_for_testing()

        c = Client()
        c.login(username="authorizer", password="0000")
        c.post(
            f"/permit/{p.id}/finalize",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
                "keep_loto_justification_comment": ["test"],
            },
        )

        # Test info notifications
        for role in Role.objects.exclude(name="worker"):
            notified_user = p.appointments.get(
                    role=Role.objects.get(name=role.name)
            ).person

            info_notif = notified_user.info_notifications.get(permit=p)
            self.assertTrue(info_notif)
            self.assertTrue(info_notif.is_active)
            self.assertFalse(info_notif.is_read)
            self.assertTrue(info_notif.target_viewname == "permitting:permit_display")

        for entry in WorkerTeam.objects.filter(permit=p):
            notified_user = entry.worker

            info_notif = notified_user.info_notifications.get(permit=p)
            self.assertTrue(info_notif)
            self.assertTrue(info_notif.is_active)
            self.assertFalse(info_notif.is_read)
            self.assertTrue(info_notif.target_viewname == "permitting:permit_display")

class RoutePermitRemoveLotoCases(TestCasesBase):
    def get_permit_for_testing(self):
        # Create permit
        p = Permit(
            status=PermitStatus.objects.get(id=12),
            task_description="test",
        )

        # Need to save here so as to receive an id for the new permit.
        p.save()

        # Appoint
        for role in Role.objects.exclude(name="worker"):
            a = Appointment(
                permit=p,
                person=User.objects.get(username=role.name),
                role=Role.objects.get(name=role.name),
            )
            a.save()

        # Appoint
        some_worker_usernames = ["w1", "w3"]

        for username in some_worker_usernames:
            person = User.objects.get(username=username)
            wt = WorkerTeam(permit=p, worker=person)

            wt.save()

        # Create mock notification to later test deactivation
        action_notif = ActionNotification(
            created_at_status=p.status,
            is_active=True,
            is_read=False,
            message="test",
            permit=p,
            target_viewname="permitting:permit_remove_loto",
            user=p.appointments.get(
                role=Role.objects.get(name="loto_officer")
            ).person,
        )
        action_notif.save()

        return p

    def test_authorization_check(self):
        c = Client()

        p = self.get_permit_for_testing()

        # Try GET without logged-in user, and get redirected to login page
        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 302)

        # Log-in a user without the required role
        c.login(username="w1", password="0000")
        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 403)

        # Log-in a user with the required role
        c.login(username="loto_officer", password="0000")
        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 200)

        # Initially `safety_gatekeeper` can't perform a GET until `loto_officer` has confirmed
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 403)

        confm = Confirmation(
            confirmed=True,
            permit=p,
            what=ConfirmationEvent.objects.get(
                short_description="loto_removed"
            )
        )
        confm.save()

        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 200)

    def test_handle_bad_form(self):
        c = Client()

        # Log-in a user with the required role
        c.login(username="loto_officer", password="0000")

        # Try GET with non-existant permit
        resp = c.get(f"/permit/9999/remove-loto")
        self.assertEqual(resp.status_code, 400)

        # Try POST with non-existant permit
        resp = c.post(
            f"/permit/9999/remove-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try GET with existing permit with incorrect status
        p = self.get_permit_for_testing()
        p.status = PermitStatus.objects.get(id=(p.status.id + 1))
        p.save()

        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 400)

        # Try POST with existing permit with incorrect status
        resp = c.post(
            f"/permit/{p.id}/remove-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 400)

        # Try POST when loto_officer has already confirmed
        p = self.get_permit_for_testing()
        confm = Confirmation(
            confirmed=True,
            permit=p,
            what=ConfirmationEvent.objects.get(
                short_description="loto_removed"
            )
        )
        confm.save()

        resp = c.post(
            f"/permit/{p.id}/remove-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )
        self.assertEqual(resp.status_code, 403)

    def test_handle_good_form_for_role1(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role & test GET method
        c.login(username="loto_officer", password="0000")
        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=13)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/remove-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check if appropriate confirmation created
        self.assertTrue(
            Confirmation.objects.filter(
                confirmed=True,
                permit=p,
                what=ConfirmationEvent.objects.get(
                    short_description="loto_removed"
                ),
            ).exists()
        )

        # Check permit status (shouldn't be updated yet!)
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            count_target_status_permits_in_db,
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_handle_good_form_for_role2(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Mock the necessary prior confirmation
        confm = Confirmation(
            confirmed=True,
            permit=p,
            what=ConfirmationEvent.objects.get(
                short_description="loto_removed"
            )
        )
        confm.save()

        # Log-in a user with the required role & test GET method
        c.login(username="safety_gatekeeper", password="0000")
        resp = c.get(f"/permit/{p.id}/remove-loto")
        self.assertEqual(resp.status_code, 200)

        # Try POST with valid form
        target_status = PermitStatus.objects.get(id=13)
        count_target_status_permits_in_db = Permit.objects.filter(
            status=target_status
        ).count()
        count_contributions_in_db = Contribution.objects.all().count()

        resp = c.post(
            f"/permit/{p.id}/remove-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Testing for code 302, because on success there will be a redirect to either single permit page or index
        self.assertEqual(resp.status_code, 302)

        # Check permit status
        self.assertEqual(
            Permit.objects.filter(status=target_status).count(),
            (count_target_status_permits_in_db + 1),
        )

        # Check if contribution added
        self.assertEqual(
            Contribution.objects.all().count(), (count_contributions_in_db + 1)
        )

    def test_db_entry_correctness_role1(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Log-in a user with the required role
        username = "loto_officer"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/remove-loto", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=12)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_db_entry_correctness_role2(self):
        c = Client()
        p = self.get_permit_for_testing()

        # Mock the necessary prior confirmation
        confm = Confirmation(
            confirmed=True,
            permit=p,
            what=ConfirmationEvent.objects.get(
                short_description="loto_removed"
            )
        )
        confm.save()

        # Log-in a user with the required role
        username = "safety_gatekeeper"
        c.login(username=username, password="0000")

        # Try POST with valid form
        post_input = {
            "csrfmiddlewaretoken": [
                "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
            ],
            "comment": ["test"],
        }

        c.post(f"/permit/{p.id}/remove-loto", post_input)

        # Test each of DB field == form's matching fields

        # Test appropriate confirmations added - tested for in `test_handle_good_form` method

        # Check status - (!!! need to re-fetch the permit status to see if it's updated !!!)
        self.assertEqual(
            Permit.objects.get(id=p.id).status, PermitStatus.objects.get(id=13)
        )

        # Check new contribution
        contrib = Contribution.objects.latest("created_on")

        self.assertEqual(contrib.author, User.objects.get(username=username))
        self.assertEqual(contrib.permit, p)

    def test_notifications_after_role1_does_post(self):
        p = self.get_permit_for_testing()

        # Do POST
        c = Client()
        c.login(username="loto_officer", password="0000")
        c.post(
            f"/permit/{p.id}/remove-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test deactivated action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="loto_officer")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertFalse(action_notif.is_active)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_remove_loto")

        # Test action notification
        notified_user = p.appointments.get(
                role=Role.objects.get(name="safety_gatekeeper")
        ).person

        action_notif = notified_user.action_notifications.get(permit=p)
        self.assertTrue(action_notif)

        p = Permit.objects.get(id=p.id)
        self.assertTrue(action_notif.created_at_status == p.status)

        self.assertTrue(action_notif.is_active)
        self.assertFalse(action_notif.is_read)
        self.assertTrue(action_notif.target_viewname == "permitting:permit_remove_loto")

    def test_notifications_after_role2_does_post(self):
        p = self.get_permit_for_testing()

        # Mock the necessary prior confirmation
        confm = Confirmation(
            confirmed=True,
            permit=p,
            what=ConfirmationEvent.objects.get(short_description="loto_removed"),
        )
        confm.save()

        # Do POST
        c = Client()
        c.login(username="safety_gatekeeper", password="0000")
        c.post(
            f"/permit/{p.id}/remove-loto",
            {
                "csrfmiddlewaretoken": [
                    "e6rVI6TZ9Sy6i2VVzRKwH6vdjkKKtsddFa3wQIuCdpzrkhOOLCGln7o2r5byKc7Q"
                ],
                "comment": ["test"],
            },
        )

        # Test info notifications
        for role in Role.objects.exclude(name="worker"):
            notified_user = p.appointments.get(
                    role=Role.objects.get(name=role.name)
            ).person

            info_notif = notified_user.info_notifications.get(permit=p)
            self.assertTrue(info_notif)
            self.assertTrue(info_notif.is_active)
            self.assertFalse(info_notif.is_read)
            self.assertTrue(info_notif.target_viewname == "permitting:permit_display")

        for entry in WorkerTeam.objects.filter(permit=p):
            notified_user = entry.worker

            info_notif = notified_user.info_notifications.get(permit=p)
            self.assertTrue(info_notif)
            self.assertTrue(info_notif.is_active)
            self.assertFalse(info_notif.is_read)
            self.assertTrue(info_notif.target_viewname == "permitting:permit_display")
