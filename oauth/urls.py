from django.conf.urls import url

from oauth.views import AuthorizeView, TokensView

app_name="oauth"

urlpatterns = [
    url('^authorize/?', AuthorizeView.as_view(), name='authorize'),
    url('^tokens/?', TokensView.as_view(), name='tokens'),
]