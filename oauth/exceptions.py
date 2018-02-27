from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException
from rest_framework import status
from rest_framework.response import Response
from django.utils.translation import ugettext_lazy as _

def custom_exception_handler(exc, context):
    """
    Formats REST exceptions like:
    {
        "error": "error_code",
        "error_description": "description of the error",
    }
    :param exc: Exception
    :return: Response
    """
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if not response:
        # Unhandled exceptions (500 internal server errors)
        response = Response(data={
            'error': 'server_error',
            'error_description': unicode(exc),
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return response

    if hasattr(exc, 'default_error'):
        response.data['error'] = exc.default_error
    else:
        response.data['error'] = 'api_error'

    if hasattr(exc, 'default_detail'):
        response.data['error_description'] = exc.default_detail
    elif 'detail' in response.data:
        response.data['error_description'] = response.data['details']

    if 'detail' in response.data:
        del response.data['detail']

    return response