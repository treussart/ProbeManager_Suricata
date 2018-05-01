import logging
import os
import time

from django import forms
from django.conf import settings
from django.conf.urls import url
from django.contrib import admin
from django.contrib import messages
from django.contrib.admin.helpers import ActionForm
from django.http import HttpResponseRedirect
from django.utils.safestring import mark_safe
from django_celery_beat.models import PeriodicTask, CrontabSchedule

from core.models import Configuration as CoreConfiguration
from core.utils import create_deploy_rules_task, add_1_hour, create_check_task
from core.utils import generic_import_csv
from .forms import SuricataChangeForm
from .models import Suricata, SignatureSuricata, ScriptSuricata, RuleSetSuricata, Configuration, \
    SourceSuricata, BlackList, IPReputation, CategoryReputation, ClassType
from .tasks import download_from_http, download_from_misp
from .utils import create_download_from_http_task, create_conf, convert_conf

logger = logging.getLogger(__name__)


class MarkedRuleMixin(admin.ModelAdmin):
    def make_enabled(self, request, queryset):
        rows_updated = queryset.update(enabled=True)
        if rows_updated == 1:
            message_bit = "1 rule was"
        else:
            message_bit = "%s rules were" % rows_updated
        self.message_user(request, "%s successfully marked as enabled." % message_bit)

    def make_disabled(self, request, queryset):
        rows_updated = queryset.update(enabled=False)
        if rows_updated == 1:
            message_bit = "1 rule was"
        else:
            message_bit = "%s rules were" % rows_updated
        self.message_user(request, "%s successfully marked as disabled." % message_bit)

    make_enabled.short_description = "Mark rule as enabled"
    make_disabled.short_description = "Mark rule as disabled"


class RuleSetSuricataAdmin(admin.ModelAdmin):

    def test_signatures(self, request, obj):
        test = True
        errors = list()
        for ruleset in obj:
            for signature in ruleset.signatures.all():
                response = signature.test()
                if not response['status']:
                    test = False
                    errors.append(str(signature) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(errors))

    actions = [test_signatures]


class SuricataAdmin(admin.ModelAdmin):
    class Media:
        js = (
            'suricata/js/mask-crontab.js',
        )

    def get_form(self, request, obj=None, **kwargs):
        """A ModelAdmin that uses a different form class when adding an object."""
        if obj is None:
            return super(SuricataAdmin, self).get_form(request, obj, **kwargs)
        else:
            return SuricataChangeForm

    def save_model(self, request, obj, form, change):
        logger.debug("create scheduled for " + str(obj))
        create_deploy_rules_task(obj)
        create_check_task(obj)
        super().save_model(request, obj, form, change)

    def test_signatures(self, request, obj):
        test = True
        errors = list()
        for probe in obj:
            response = probe.test_rules()
            if not response['status']:
                test = False
                errors.append(str(probe) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(errors))

    actions = [test_signatures]


class ConfigurationAdmin(admin.ModelAdmin):
    class Media:
        js = (
            'suricata/js/mask-advanced-fields.js',
        )

    def save_model(self, request, obj, form, change):
        if not obj.conf_advanced:
            obj = create_conf(obj)
        else:
            obj = convert_conf(obj)
        response = obj.test()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test configuration OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configuration failed ! " + str(response['errors']))
        super().save_model(request, obj, form, change)

    def test_configurations(self, request, obj):
        test = True
        errors = list()
        for conf in obj:
            response = conf.test()
            if not response['status']:
                test = False
                errors.append(str(conf) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test configurations OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configurations failed ! " + str(errors))

    actions = [test_configurations]


class ScriptSuricataAdmin(MarkedRuleMixin, admin.ModelAdmin):

    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetsuricata__name')
    list_display = ('id', 'name', 'enabled')
    actions = [MarkedRuleMixin.make_enabled, MarkedRuleMixin.make_disabled]


class SignatureSuricataAdmin(MarkedRuleMixin, admin.ModelAdmin):

    def add_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.add(signature)
            ruleset.save()

    add_ruleset.short_description = 'Add ruleset'

    def remove_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.remove(signature)
            ruleset.save()

    remove_ruleset.short_description = 'Remove ruleset'

    class UpdateActionForm(ActionForm):
        ruleset = forms.ModelChoiceField(queryset=RuleSetSuricata.get_all(), empty_label="Select a ruleset",
                                         required=False)

    def test_signatures(self, request, obj):
        test = True
        errors = list()
        for signature in obj:
            response = signature.test_all()
            if not response['status']:
                test = False
                errors.append(str(signature) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test signatures OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signatures failed ! " + str(errors))

    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetsuricata__name')
    list_display = ('sid', 'msg', 'enabled')
    action_form = UpdateActionForm
    actions = [MarkedRuleMixin.make_enabled, MarkedRuleMixin.make_disabled,
               add_ruleset, remove_ruleset, test_signatures]

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        response = obj.test_all()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test signature OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signature failed ! " + str(response['errors']))

    class Media:
        js = (
            'suricata/js/add-link-reference.js',
            'suricata/js/mask-ruleset-field.js',
        )


class SourceSuricataAdmin(admin.ModelAdmin):

    def get_actions(self, request):
        actions = super(SourceSuricataAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def delete_source(self, request, obj):
        for source in obj:
            try:
                periodic_task = PeriodicTask.objects.get(name=source.uri + '_download_from_http_task')
                periodic_task.delete()
                logger.debug(str(periodic_task) + " deleted")
            except PeriodicTask.DoesNotExist:
                pass
            try:
                for ruleset in source.rulesets.all():
                    for probe in ruleset.suricata_set.all():
                        periodic_task = PeriodicTask.objects.get(
                            name__contains=probe.name + "_" + source.uri + "_deploy_rules_")
                        periodic_task.delete()
                        logger.debug(str(periodic_task) + " deleted")
            except PeriodicTask.DoesNotExist:
                pass
            source.delete()
            logger.debug(str(source) + " deleted")
            messages.add_message(request, messages.SUCCESS, str(source) + " deleted")

    actions = [delete_source]
    list_display = ('__str__',)
    list_display_links = None

    def response_add(self, request, obj, post_url_continue=None):
        """
        Determines the HttpResponse for the add_view stage.
        """
        if obj.method.name == "Upload file":
            for source in SourceSuricata.get_all():
                if '_to_delete' in source.uri:
                    source.delete()
            return HttpResponseRedirect('/')
        else:
            return super(SourceSuricataAdmin, self).response_change(request, obj)

    def save_model(self, request, obj, form, change):
        try:
            rulesets = list()
            rulesets_id = list()
            if request.POST.getlist('rulesets'):
                rulesets_id = request.POST.getlist('rulesets')
                for ruleset_id in rulesets_id:
                    rulesets.append(RuleSetSuricata.get_by_id(ruleset_id))
            # URL HTTP
            if obj.method.name == "URL HTTP":
                obj.save()
                if obj.scheduled_rules_deployment_enabled and obj.scheduled_rules_deployment_crontab:
                    create_download_from_http_task(obj)
                    if obj.scheduled_deploy:
                        if rulesets:
                            for ruleset in rulesets:
                                try:
                                    for probe in ruleset.suricata_set.all():
                                        schedule = add_1_hour(obj.scheduled_rules_deployment_crontab)
                                        schedule, _ = CrontabSchedule.objects.\
                                            get_or_create(minute=schedule.minute,
                                                          hour=schedule.hour,
                                                          day_of_week=schedule.day_of_week,
                                                          day_of_month=schedule.day_of_month,
                                                          month_of_year=schedule.month_of_year,
                                                          )
                                        schedule.save()
                                        create_deploy_rules_task(probe, schedule, obj)
                                except Exception as e:  # pragma: no cover
                                    logger.exception(str(e))
                download_from_http.delay(obj.uri, rulesets_id=rulesets_id)
                messages.add_message(request, messages.SUCCESS, mark_safe("Upload source in progress. " +
                                     "<a href='/admin/core/job/'>View Job</a>"))
            # Upload file
            elif obj.method.name == "Upload file":
                obj.uri = str(time.time()) + "_to_delete"
                obj.save()
                count_signature_created, count_signature_updated, count_script_created, count_script_updated = \
                    obj.download_from_file(request.FILES['file'].name, rulesets)
                message = 'File uploaded successfully : ' + str(count_signature_created) + \
                          ' signature(s) created and ' + str(count_signature_updated) + \
                          ' signature(s) updated -  ' + str(count_script_created) + \
                          ' script(s) created and ' + str(count_script_updated) + ' script(s) updated'
                logger.debug("Upload file: " + str(message))
                messages.add_message(request, messages.SUCCESS, message)
            # MISP
            elif obj.method.name == "MISP":
                obj.uri = CoreConfiguration.get_value("MISP_HOST")
                obj.save()
                logger.debug("Uploading rules from MISP")
                download_from_misp.delay(obj.uri, rulesets_id=rulesets_id)
                messages.add_message(request, messages.SUCCESS,
                                     mark_safe("Upload source in progress. " +
                                               "<a href='/admin/core/job/'>View Job</a>"))
            else:  # pragma: no cover
                logger.error('Upload method unknown : ' + obj.method.name)
                messages.add_message(request, messages.ERROR, 'Upload method unknown : ' + obj.method.name)
        except Exception as e:  # pragma: no cover
            logger.exception(str(e))
            messages.add_message(request, messages.ERROR, str(e))
        finally:
            if os.path.isfile(settings.BASE_DIR + "/" + obj.file.name):
                os.remove(settings.BASE_DIR + "/" + obj.file.name)

    class Media:
        js = (
            'suricata/js/add-link-reference.js',
            'suricata/js/method-options.js',
        )


class BlackListAdmin(admin.ModelAdmin):
    list_display = ('__str__',)
    list_display_links = None


class IPReputationAdmin(admin.ModelAdmin):

    def get_urls(self):
        urls = super().get_urls()
        my_urls = [url(r'^import_csv/$', self.import_csv, name="import_csv_ip_rep"), ]
        return my_urls + urls

    def import_csv(self, request):
        return generic_import_csv(IPReputation, request)


class CategoryReputationAdmin(admin.ModelAdmin):

    def get_urls(self):
        urls = super().get_urls()
        my_urls = [url(r'^import_csv/$', self.import_csv, name="import_csv_cat_rep"), ]
        return my_urls + urls

    def import_csv(self, request):
        return generic_import_csv(CategoryReputation, request)


admin.site.register(Suricata, SuricataAdmin)
admin.site.register(SignatureSuricata, SignatureSuricataAdmin)
admin.site.register(ScriptSuricata, ScriptSuricataAdmin)
admin.site.register(RuleSetSuricata, RuleSetSuricataAdmin)
admin.site.register(Configuration, ConfigurationAdmin)
admin.site.register(SourceSuricata, SourceSuricataAdmin)
admin.site.register(BlackList, BlackListAdmin)
admin.site.register(IPReputation, IPReputationAdmin)
admin.site.register(CategoryReputation, CategoryReputationAdmin)
admin.site.register(ClassType)
