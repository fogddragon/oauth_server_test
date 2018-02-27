from django.http import HttpResponse
from django.shortcuts import render
from django.views import View
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from oauth.forms import AuthorizeForm
from oauth.models import Scope, Client
from oauth.responsetypes import response_factory, grant_factory
from oauth.serializers import OAuthAccessTokenSerializer
from oauth.validator import  validate_token


class AuthorizeView(View):
    form_class = AuthorizeForm
    initial = {}
    template_name = 'web/authorize.html'

    def dispatch(self, *args, **kwargs):
        try:
            self.request.client = Client.objects.get(
                client_id=self.request.GET['client_id'])
        except KeyError:
            return HttpResponse(render(self.request, 'web/error.html', {
                'title': 'Error',
                'error': u'invalid_client',
                'error_description': u'No client id supplied'
            }))
        except Client.DoesNotExist:
            return HttpResponse(render(self.request, 'web/error.html', {
                'title': 'Error',
                'error': u'invalid_client',
                'error_description': u'The client id supplied is invalid',
            }))
        self.request.response_type = self.request.GET.get('response_type', None)
        if not self.request.response_type or self.request.response_type not in ('code', 'token'):
            return HttpResponse(render(self.request, 'web/error.html', {
                'title': 'Error',
                'error': u'invalid_request',
                'error_description': u'Invalid or missing response type',
            }))
        self.request.redirect_uri = self.request.GET.get('redirect_uri', None)
        if not self.request.redirect_uri:
            return HttpResponse(render(self.request, 'web/error.html', {
                'title': 'Error',
                'error': u'invalid_uri',
            }))
        return super(AuthorizeView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return self._render(request=request, form=form)

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if not form.is_valid():
            return self._render(request=request, form=form)

        return response_factory(response_type=request.response_type).process(
            client=request.client,
            authorized=form.cleaned_data['authorize'],
            scopes=form.cleaned_data['scopes'],
            redirect_uri=request.redirect_uri,
            state=request.state,
        )

    def _render(self, request, form):
        return HttpResponse(render(request, self.template_name, {
            'title': 'Authorize', 'client': request.client,
            'form': form, 'scopes': Scope.objects.all()}))


class TokensView(APIView):

    def post(self, request, *args, **kwargs):
        validate_token(request, *args, **kwargs)
        access_token = grant_factory(request=request).grant()
        return Response(
            OAuthAccessTokenSerializer(access_token).data,
            status=status.HTTP_201_CREATED,
        )