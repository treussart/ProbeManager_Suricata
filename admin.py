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
from django_celery_beat.models import CrontabSchedule

from core.models import Configuration as CoreConfiguration
from core.utils import create_deploy_rules_task, add_1_hour
from core.views import generic_import_csv
from .forms import SuricataChangeForm
from .models import Suricata, SignatureSuricata, ScriptSuricata, RuleSetSuricata, Configuration, \
    SourceSuricata, BlackList, IPReputation, CategoryReputation, ClassType
from .tasks import download_from_http, download_from_misp
from .utils import create_download_from_http_task

logger = logging.getLogger(__name__)


class RuleMixin(admin.ModelAdmin):
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

    class UpdateActionForm(ActionForm):
        ruleset = forms.ModelChoiceField(queryset=RuleSetSuricata.get_all(), empty_label="Select a ruleset",
                                         required=False)

    class Media:
        js = (
            'suricata/js/add-link-reference.js',
            'suricata/js/mask-ruleset-field.js',
        )

    def test(self, request, obj):
        test = True
        errors = list()
        for rule in obj:
            response = rule.test_all()
            if not response['status']:
                test = False
                errors.append(str(rule) + " : " + str(response['errors']))
        if test:
            messages.add_message(request, messages.SUCCESS, "Test OK")
        else:
            messages.add_message(request, messages.ERROR, "Test failed ! " + str(errors))


class RuleSetSuricataAdmin(admin.ModelAdmin):
    def test_rules(self, request, obj):
        test = True
        errors = list()
        for ruleset in obj:
            response = ruleset.test_rules()
            if not response['status']:
                test = False
                errors.append(response['errors'])
        if test:
            messages.add_message(request, messages.SUCCESS, "Test rules OK")
        else:
            messages.add_message(request, messages.ERROR, "Test rules failed ! " + str(errors))

    actions = [test_rules]


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
        super().save_model(request, obj, form, change)
        conf = Configuration.objects.get(name=obj.name)
        response = conf.test()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test configuration OK")
        else:
            messages.add_message(request, messages.ERROR, "Test configuration failed ! " + str(response['errors']))

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


class ScriptSuricataAdmin(RuleMixin, admin.ModelAdmin):
    def add_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.scripts.add(signature)
            ruleset.save()
            messages.add_message(request, messages.SUCCESS, "Added to Ruleset "
                                 + ruleset.name + " successfully !")

    def remove_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.scripts.remove(signature)
            ruleset.save()
            messages.add_message(request, messages.SUCCESS, "Removed from Ruleset "
                                 + ruleset.name + " successfully !")

    add_ruleset.short_description = 'Add ruleset'
    remove_ruleset.short_description = 'Remove ruleset'
    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetsuricata__name')
    list_display = ('id', 'filename', 'enabled')
    action_form = RuleMixin.UpdateActionForm
    actions = [RuleMixin.make_enabled, RuleMixin.make_disabled, add_ruleset, remove_ruleset]


class SignatureSuricataAdmin(RuleMixin, admin.ModelAdmin):
    def add_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.add(signature)
            ruleset.save()
            messages.add_message(request, messages.SUCCESS, "Added to Ruleset "
                                 + ruleset.name + " successfully !")

    def remove_ruleset(self, request, queryset):
        ruleset_id = request.POST['ruleset']
        if ruleset_id:
            ruleset = RuleSetSuricata.get_by_id(ruleset_id)
            for signature in queryset:
                ruleset.signatures.remove(signature)
            ruleset.save()
            messages.add_message(request, messages.SUCCESS, "Removed from Ruleset "
                                 + ruleset.name + " successfully !")

    add_ruleset.short_description = 'Add ruleset'
    remove_ruleset.short_description = 'Remove ruleset'
    RuleMixin.test.short_description = "Test Signature"
    search_fields = ('rule_full',)
    list_filter = ('enabled', 'created_date', 'updated_date', 'rulesetsuricata__name')
    list_display = ('sid', 'msg', 'enabled')
    action_form = RuleMixin.UpdateActionForm
    actions = [RuleMixin.make_enabled, RuleMixin.make_disabled,
               add_ruleset, remove_ruleset, RuleMixin.test]

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        response = obj.test_all()
        if response['status']:
            messages.add_message(request, messages.SUCCESS, "Test signature OK")
        else:
            messages.add_message(request, messages.ERROR, "Test signature failed ! " + str(response['errors']))


class SourceSuricataAdmin(admin.ModelAdmin):
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
