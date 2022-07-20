import re

from django.core import validators
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _


@deconstructible
class LowercaseASCIIUsernameValidator(validators.RegexValidator):
    regex = r'^[0-9a-z-_]+\Z'
    message = _(
        'Enter a valid username. This value may contain only lowercase English letters, '
        'numbers, and -/_ characters.'
    )
    flags = re.ASCII


class LowercaseASCIIGroupnameValidator(LowercaseASCIIUsernameValidator):
    message = _(
        'Enter a valid group name. This value may contain only lowercase English letters, '
        'numbers, and -/_ characters.'
    )
