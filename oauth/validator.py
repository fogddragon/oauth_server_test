import base64

from django.conf import settings
from rest_framework.exceptions import APIException
from rest_framework import status

from oauth.models import AuthorizationCode, User, RefreshToken, Client, Scope

def validate_token(request, *args, **kwargs):
    grant_type = request.POST.get('grant_type', None)

    if not grant_type:
        raise APIException(
            status_code = status.HTTP_400_BAD_REQUEST,
            default_error = u'invalid_request',
            default_detail = u'The grant type was not specified in the request'
        )

    valid_grant_types = (
        'client_credentials',
        'authorization_code',
        'password',
        'refresh_token',
    )
    if grant_type not in valid_grant_types:
        raise APIException(
            status_code=status.HTTP_400_BAD_REQUEST,
            default_error = u'invalid_request',
            default_detail = u'Invalid grant type'
        )

    # authorization_code grant requires code parameter
    if grant_type == 'authorization_code':
        try:
            auth_code = request.POST['code']
        except KeyError:
            try:
                auth_code = request.GET['code']
            except KeyError:
                raise APIException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    default_error = u'invalid_request',
                    default_detail = u'The code parameter is required'
                )

    # password grant requires username and password parameters
    if grant_type == 'password':
        try:
            username = request.POST['username']
        except KeyError:
            try:
                username = request.GET['username']
            except KeyError:
                raise APIException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    default_error=u'invalid_request',
                    default_detail=u'The username parameter is required'
                )
        try:
            password = request.POST['password']
        except KeyError:
            try:
                password = request.GET['password']
            except KeyError:
                raise APIException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    default_error=u'invalid_request',
                    default_detail=u'The password parameter is required'
                )

    # refresh_token grant requires refresh_token parameter
    if grant_type == 'refresh_token':
        try:
            refresh_token = request.POST['refresh_token']
        except KeyError:
            try:
                refresh_token = request.GET['refresh_token']
            except KeyError:
                raise APIException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        default_error=u'invalid_request',
                        default_detail=u'The refresh token parameter is required'
                    )

    if grant_type == 'authorization_code':
        try:
            request.auth_code = AuthorizationCode.objects.get(
                code=auth_code)
        except AuthorizationCode.DoesNotExist:
            raise APIException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    default_error=u'invalid_request',
                    default_detail=u'Authorization code not found'
                )

    if grant_type == 'password':
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            raise APIException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                default_error=u'invalid_user',
                default_detail=u'Invalid user credentials'
            )

        if not user.verify_password(password):
            raise APIException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                default_error=u'invalid_user',
                default_detail=u'Invalid user credentials'
            )

        request.user = user

    if grant_type == 'refresh_token':
        try:
            request.refresh_token = RefreshToken.objects.get(
                refresh_token=refresh_token)
        except RefreshToken.DoesNotExist:
            raise APIException(
                status_code=status.HTTP_400_BAD_REQUEST,
                default_error=u'invalid_request',
                default_detail=u'Refresh token not found',
            )

    request.grant_type = grant_type
    client_id, client_secret = None, None

    # First, let's check Authorization header if present
    if 'HTTP_AUTHORIZATION' in request.META:
        auth_method, auth = request.META['HTTP_AUTHORIZATION'].split(': ')
        if auth_method.lower() == 'basic':
            client_id, client_secret = base64.b64decode(auth).split(':')

    # Fallback to POST and then to GET
    if not client_id or not client_secret:
        try:
            client_id = request.POST['client_id']
            client_secret = request.POST['client_secret']
        except KeyError:
            try:
                client_id = request.GET['client_id']
                client_secret = request.GET['client_secret']
            except KeyError:
                raise APIException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    default_error=u'invalid_client',
                    default_detail=u'Client credentials were not found in the headers or body'
                )
    try:
        client = Client.objects.get(client_id=client_id)
    except Client.DoesNotExist:
        raise APIException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            default_error=u'invalid_client',
            default_detail=u'Invalid client credentials'
        )
    if not client.verify_password(client_secret):
        raise APIException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            default_error=u'invalid_client',
            default_detail=u'Invalid client credentials'
        )

    request.client = client
    if request.grant_type not in ('client_credentials', 'password'):
        return

    if settings.OAUTH2_SERVER['IGNORE_CLIENT_REQUESTED_SCOPE']:
        request.scopes = Scope.objects.filter(is_default=True)
        return

    try:
        scopes = request.POST['scope'].split(' ')
    except KeyError:
        try:
            scopes = request.GET['scope'].split(' ')
        except KeyError:
            scopes = []

    request.scopes = Scope.objects.filter(scope__in=scopes)

    # Fallback to the default scope if no scope sent with the request
    if len(request.scopes) == 0:
        request.scopes = Scope.objects.filter(is_default=True)