from django.forms import ModelForm

from .models import Suricata


class SuricataChangeForm(ModelForm):
    class Meta:
        model = Suricata
        fields = ('name',
                  'description',
                  'installed',
                  'secure_deployment',
                  'server',
                  'rulesets',
                  'configuration'
                  )
