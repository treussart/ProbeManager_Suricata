from rest_framework import viewsets
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin

from suricata.api.serializers import ConfigurationSerializer, SuricataSerializer, SignatureSuricataSerializer, \
    ScriptSuricataSerializer, SourceSuricataSerializer, RuleSetSuricataSerializer
from suricata.models import Suricata, Configuration, SignatureSuricata, ScriptSuricata, SourceSuricata, RuleSetSuricata


class ConfigurationViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer


class SuricataViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Suricata.objects.all()
    serializer_class = SuricataSerializer


class SignatureSuricataViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = SignatureSuricata.objects.all()
    serializer_class = SignatureSuricataSerializer


class ScriptSuricataViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = ScriptSuricata.objects.all()
    serializer_class = ScriptSuricataSerializer


class SourceSuricataViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = SourceSuricata.objects.all()
    serializer_class = SourceSuricataSerializer


class RuleSetSuricataViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = RuleSetSuricata.objects.all()
    serializer_class = RuleSetSuricataSerializer
