from django import forms

from .models import (
    AreaRelatedRisk,
    CollectiveProtection,
    Equipment,
    PersonalProtection,
    Role,
    SafetyMeasure,
)


class ApplicationToFinalizeForm(forms.Form):
    performed_tests_and_golive_procedures_description = forms.CharField(
        max_length=256,
        required=True,
        widget=forms.Textarea(
            attrs={
                "class": "form-control mb-3 mx-auto w-50",
                "id": "tests-and-golive-comment-field",
                "placeholder": "Describe the tests that were performed, and add any notes you may have on putting the equipment back into operation.",
                "rows": "3",
            }
        ),
    )

    comment = forms.CharField(
        max_length=256,
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control mb-3 mx-auto w-50",
                "id": "contribution-comment-field",
                "placeholder": "(Optional text)",
                "rows": "2",
            }
        ),
    )


class AuthorizationForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            eligibles = Role.objects.get(name="loto_officer").eligible.all()
        except Role.DoesNotExist:
            eligibles = []

        OPTIONS = [
            (
                option.id,
                f"{option.username} {f"of '{option.org.name}'" if option.org else ""}",
            )
            for option in eligibles
        ]
        self.fields["loto_officer"].choices = OPTIONS

        try:
            eligibles = Role.objects.get(name="safety_gatekeeper").eligible.all()
        except Role.DoesNotExist:
            eligibles = []

        OPTIONS = [
            (
                option.id,
                f"{option.username} {f"of '{option.org.name}'" if option.org else ""}",
            )
            for option in eligibles
        ]
        self.fields["safety_gatekeeper"].choices = OPTIONS

    loto_officer = forms.ChoiceField(
        required=True,
        widget=forms.Select(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    safety_gatekeeper = forms.ChoiceField(
        required=True,
        widget=forms.Select(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    comment = forms.CharField(
        max_length=256,
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control mb-3 mx-auto w-50",
                "id": "contribution-comment-field",
                "placeholder": "(Optional text)",
                "rows": "2",
            }
        ),
    )


class NewPermitForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Tip by ddb: Need to get the options values at initiallization.
        # Otherwise (if delclared below), they are retrieved before other logic in view functions etc.
        OPTIONS = [(option.id, option.tag) for option in Equipment.objects.all()]
        OPTIONS.append(("", ""))
        self.fields["targeted_equipment"].choices = OPTIONS

        OPTIONS = [(option.id, option.name) for option in AreaRelatedRisk.objects.all()]
        self.fields["risks"].choices = OPTIONS

        OPTIONS = [
            (option.id, option.name) for option in PersonalProtection.objects.all()
        ]
        self.fields["personal_protection"].choices = OPTIONS

        OPTIONS = [
            (option.id, option.name) for option in CollectiveProtection.objects.all()
        ]
        self.fields["collective_protection"].choices = OPTIONS

        OPTIONS = [(option.id, option.name) for option in SafetyMeasure.objects.all()]
        self.fields["safety_measures"].choices = OPTIONS

        try:
            eligibles = Role.objects.get(name="task_responsible").eligible.all()
        except Role.DoesNotExist:
            eligibles = []

        OPTIONS = [
            (
                option.id,
                f"{option.username} {f"of '{option.org.name}'" if option.org else ""}",
            )
            for option in eligibles
        ]
        OPTIONS.append(("", ""))
        self.fields["task_responsible"].choices = OPTIONS

    task_description = forms.CharField(
        max_length=256,
        widget=forms.Textarea(
            attrs={"class": "form-control mb-3 mx-auto w-50", "rows": "4"}
        ),
    )

    targeted_equipment = forms.ChoiceField(
        required=True,
        widget=forms.Select(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    risks = forms.MultipleChoiceField(
        required=True,
        widget=forms.SelectMultiple(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    personal_protection = forms.MultipleChoiceField(
        required=True,
        widget=forms.SelectMultiple(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    collective_protection = forms.MultipleChoiceField(
        required=True,
        widget=forms.SelectMultiple(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    safety_measures = forms.MultipleChoiceField(
        required=True,
        widget=forms.SelectMultiple(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    task_responsible = forms.ChoiceField(
        required=True,
        widget=forms.Select(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    comment = forms.CharField(
        max_length=256,
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control mb-3 mx-auto w-50",
                "id": "contribution-comment-field",
                "placeholder": "(Optional text)",
                "rows": "2",
            }
        ),
    )


class SingleCommentForm(forms.Form):
    comment = forms.CharField(
        max_length=256,
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control mb-3 mx-auto w-50",
                "id": "contribution-comment-field",
                "placeholder": "(Optional text)",
                "rows": "2",
            }
        ),
    )


class StaffSelectionForm(forms.Form):
    def __init__(self, *args, org=None, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            eligibles = Role.objects.get(name="foreman").eligible.filter(org=org)
        except Role.DoesNotExist:
            eligibles = []

        OPTIONS = [
            (
                option.id,
                f"{option.username} {f"of '{option.org.name}'" if option.org else ""}",
            )
            for option in eligibles
        ]
        self.fields["foreman"].choices = OPTIONS

        try:
            eligibles = Role.objects.get(name="worker").eligible.filter(org=org)
        except Role.DoesNotExist:
            eligibles = []

        OPTIONS = [
            (
                option.id,
                f"{option.username} {f"of '{option.org.name}'" if option.org else ""}",
            )
            for option in eligibles
        ]
        self.fields["workers"].choices = OPTIONS

    foreman = forms.ChoiceField(
        required=True,
        widget=forms.Select(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    workers = forms.MultipleChoiceField(
        required=True,
        widget=forms.SelectMultiple(attrs={"class": "form-control mb-3 mx-auto w-50"}),
    )

    comment = forms.CharField(
        max_length=256,
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control mb-3 mx-auto w-50",
                "id": "contribution-comment-field",
                "placeholder": "(Optional text)",
                "rows": "2",
            }
        ),
    )
