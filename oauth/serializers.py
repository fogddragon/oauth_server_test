from rest_framework import serializers

from oauth.models import AccessToken


class OAuthAccessTokenSerializer(serializers.ModelSerializer):

    refresh_token = serializers.CharField(
        source='refresh_token.refresh_token')

    class Meta:
        model = AccessToken
        fields = (
            'id',
            'access_token',
            'expires_in',
            'token_type',
            'scope',
            'refresh_token',
        )