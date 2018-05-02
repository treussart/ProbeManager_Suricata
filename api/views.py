import logging

from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action

from suricata.api import serializers
from suricata.models import Suricata, Configuration, SignatureSuricata, ScriptSuricata, SourceSuricata, \
    RuleSetSuricata, BlackList, IPReputation, CategoryReputation, ClassType

logger = logging.getLogger(__name__)


class ClassTypeViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows class type to be viewed or edited. ex : Not Suspicious Traffic
    """
    queryset = ClassType.objects.all()
    serializer_class = serializers.ClassTypeSerializer


class ConfigurationViewSet(viewsets.ModelViewSet):
    queryset = Configuration.objects.all()
    serializer_class = serializers.ConfigurationSerializer

    @action(detail=True)
    def test(self, request, pk=None):
        obj = self.get_object()
        response = obj.test()
        return Response(response)


class SuricataViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin,
                      mixins.CreateModelMixin, viewsets.GenericViewSet):
    queryset = Suricata.objects.all()
    serializer_class = serializers.SuricataSerializer

    def update(self, request, pk=None):
        suricata = self.get_object()
        serializer = serializers.SuricataUpdateSerializer(suricata, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        suricata = self.get_object()
        serializer = serializers.SuricataUpdateSerializer(suricata, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True)
    def test_rules(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_rules()
        return Response(response)

    @action(detail=True)
    def start(self, request, pk=None):
        obj = self.get_object()
        response = obj.start()
        return Response(response)

    @action(detail=True)
    def stop(self, request, pk=None):
        obj = self.get_object()
        response = obj.stop()
        return Response(response)

    @action(detail=True)
    def restart(self, request, pk=None):
        obj = self.get_object()
        response = obj.restart()
        return Response(response)

    @action(detail=True)
    def reload(self, request, pk=None):
        obj = self.get_object()
        response = obj.reload()
        return Response(response)

    @action(detail=True)
    def status(self, request, pk=None):
        obj = self.get_object()
        response = obj.status()
        return Response({'status': response})

    @action(detail=True)
    def uptime(self, request, pk=None):
        obj = self.get_object()
        response = obj.uptime()
        return Response({'uptime': response})

    @action(detail=True)
    def deploy_rules(self, request, pk=None):
        obj = self.get_object()
        response = obj.deploy_rules()
        return Response(response)

    @action(detail=True)
    def deploy_conf(self, request, pk=None):
        obj = self.get_object()
        response = obj.deploy_conf()
        return Response(response)

    @action(detail=True)
    def install(self, request, pk=None):
        obj = self.get_object()
        try:
            version = request.query_params['version']
            response = obj.install(version=version)
        except KeyError:
            response = obj.install()
        return Response(response)


class SignatureSuricataViewSet(viewsets.ModelViewSet):
    queryset = SignatureSuricata.objects.all()
    serializer_class = serializers.SignatureSuricataSerializer

    @action(detail=True)
    def test(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_all()
        return Response(response)


class ScriptSuricataViewSet(viewsets.ModelViewSet):
    queryset = ScriptSuricata.objects.all()
    serializer_class = serializers.ScriptSuricataSerializer

    @action(detail=True)
    def test(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_all()
        return Response(response)


class SourceSuricataViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = SourceSuricata.objects.all()
    serializer_class = serializers.SourceSuricataSerializer


class RuleSetSuricataViewSet(viewsets.ModelViewSet):
    queryset = RuleSetSuricata.objects.all()
    serializer_class = serializers.RuleSetSuricataSerializer

    @action(detail=True)
    def test_rules(self, request, pk=None):
        obj = self.get_object()
        response = obj.test_rules()
        return Response(response)


class BlackListViewSet(viewsets.ModelViewSet):
    queryset = BlackList.objects.all()
    serializer_class = serializers.BlackListSerializer


class IPReputationViewSet(viewsets.ModelViewSet):
    queryset = IPReputation.objects.all()
    serializer_class = serializers.IPReputationSerializer


class CategoryReputationViewSet(viewsets.ModelViewSet):
    queryset = CategoryReputation.objects.all()
    serializer_class = serializers.CategoryReputationSerializer
