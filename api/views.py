from rest_framework import viewsets
from suricata.api.serializers import ClassTypeSerializer, ConfSuricataSerializer, SuricataSerializer, SignatureSuricataSerializer, ScriptSuricataSerializer, SourceSuricataSerializer, RuleSetSuricataSerializer, AppLayerTypeSerializer
from suricata.models import Suricata, ConfSuricata, SignatureSuricata, ScriptSuricata, SourceSuricata, RuleSetSuricata, AppLayerType
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin


class ConfSuricataViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = ConfSuricata.objects.all()
    serializer_class = ConfSuricataSerializer


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


class AppLayerTypeViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = AppLayerType.objects.all()
    serializer_class = AppLayerTypeSerializer
