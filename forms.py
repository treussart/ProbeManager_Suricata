from django.forms import ModelForm
from suricata.models import Suricata


class SuricataChangeForm(ModelForm):
    class Meta:
        model = Suricata
        fields = ('name', 'description', 'secure_deployment', 'server', 'rulesets', 'configuration')
