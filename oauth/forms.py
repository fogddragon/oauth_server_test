from django import forms

from oauth.models import Scope


class AuthorizeForm(forms.Form):

    authorize = forms.BooleanField()
    scopes = forms.ModelMultipleChoiceField(
        queryset=Scope.objects.all(),
        widget=forms.CheckboxSelectMultiple)