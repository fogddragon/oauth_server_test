from datetime import timezone

from django.conf import settings
from django.db import models
from django.core.validators import EmailValidator, ValidationError
from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt", ],
    default="bcrypt",

    # vary rounds parameter randomly when creating new hashes...
    all__vary_rounds = 0.1,

    # set the number of rounds that should be used...
    # (appropriate values may vary for different schemes,
    # and the amount of time you wish it to take)
    bcrypt__default_rounds = 12, # default for bcrypt
)

class Credentials():

    class Meta:
        abstract = True


class User(models.Model):

    email = models.CharField(
        max_length=254,
        unique=True,
        validators=[EmailValidator()],
    )
    password = models.CharField(max_length=160)

    def __unicode__(self):
        return self.email

    def validate_unique(self, exclude=None):
        if self.pk is None:
            queryset = User.objects.filter(email__iexact=self.email)
        else:
            queryset = User.objects.filter(email__iexact=self.email)\
                .exclude(pk=self.pk)
        if len(queryset) != 0:
            raise ValidationError(u'Email not unique')

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.password = pwd_context.encrypt(secret=self.password)
        elif not pwd_context.identify(hash=self.password):
            self.password = pwd_context.encrypt(secret=self.password)
        super(User, self).save(*args, **kwargs)

    def verify_password(self, raw_password):
        return pwd_context.verify(secret=raw_password, hash=self.password)


class Client(models.Model):

    client_id = models.CharField(
        max_length=254,
        unique=True,
        validators=[EmailValidator()],
    )
    redirect_uri = models.CharField(max_length=200, null=True)
    password = models.CharField(max_length=160)

    def __unicode__(self):
        return self.client_id

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.password = pwd_context.encrypt(secret=self.password)
        elif not pwd_context.identify(hash=self.password):
            self.password = pwd_context.encrypt(secret=self.password)
        super(Client, self).save(*args, **kwargs)

    def verify_password(self, raw_password):
        return pwd_context.verify(secret=raw_password, hash=self.password)


class ExpiresMixin(models.Model):
    expires_at = models.DateTimeField()

    class Meta:
        abstract = True

    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def expires_in(self):
        now = timezone.now()
        if now >= self.expires_at:
            return 0
        return int(round((self.expires_at - now).total_seconds()))

    @classmethod
    def new_expires_at(cls):
        try:
            lifetime = settings.OAUTH2_SERVER[cls.lifetime_setting]
        except KeyError:
            lifetime = cls.default_lifetime
        return timezone.now() + timezone.timedelta(seconds=lifetime)


class Scope(models.Model):
    """
    See http://tools.ietf.org/html/rfc6749#section-3.3
    """

    scope = models.CharField(max_length=200, unique=True)
    description = models.TextField()
    is_default = models.BooleanField(default=False)

    def __unicode__(self):
        return self.scope


class TokenCodeMixin(models.Model):

    scopes = models.ManyToManyField(Scope)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, )
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE, )

    @property
    def scope(self):
        return ' '.join([s.scope for s in self.scopes.all()])

    class Meta:
        abstract = True


class RefreshToken(ExpiresMixin):

    refresh_token = models.CharField(max_length=40, unique=True)

    def __unicode__(self):
        return self.token

    lifetime_setting = 'REFRESH_TOKEN_LIFETIME'
    default_lifetime = 1209600  # 14 days


class AccessToken(TokenCodeMixin, ExpiresMixin):

    access_token = models.CharField(max_length=40, unique=True)
    refresh_token = models.OneToOneField(
        RefreshToken, null=True, related_name='access_token', on_delete=models.CASCADE,
    )

    @property
    def token_type(self):
        return 'Bearer'

    def __unicode__(self):
        return self.token

    lifetime_setting = 'ACCESS_TOKEN_LIFETIME'
    default_lifetime = 3600


class AuthorizationCode(TokenCodeMixin, ExpiresMixin):

    code = models.CharField(max_length=40, unique=True)
    redirect_uri = models.CharField(max_length=200, null=True)

    def __unicode__(self):
        return self.code

    lifetime_setting = 'AUTH_CODE_LIFETIME'
    default_lifetime = 3600