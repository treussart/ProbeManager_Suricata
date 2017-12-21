django.jQuery(document).ready(function(){
    if(django.jQuery('#id_scheduled_rules_deployment_enabled').is(':checked')){
        django.jQuery('.form-row.field-scheduled_rules_deployment_crontab').show();
    } else {
        django.jQuery('.form-row.field-scheduled_rules_deployment_crontab').hide();
    }
    django.jQuery('#id_scheduled_rules_deployment_enabled').change(function(){
        if(django.jQuery('#id_scheduled_rules_deployment_enabled').is(':checked')){
            django.jQuery('.form-row.field-scheduled_rules_deployment_crontab').show();
        } else {
            django.jQuery('.form-row.field-scheduled_rules_deployment_crontab').hide();
        }
    });
});

django.jQuery(document).ready(function(){
    if(django.jQuery('#id_scheduled_check_enabled').is(':checked')){
        django.jQuery('.form-row.field-scheduled_check_crontab').show();
    } else {
        django.jQuery('.form-row.field-scheduled_check_crontab').hide();
    }
    django.jQuery('#id_scheduled_check_enabled').change(function(){
        if(django.jQuery('#id_scheduled_check_enabled').is(':checked')){
            django.jQuery('.form-row.field-scheduled_check_crontab').show();
        } else {
            django.jQuery('.form-row.field-scheduled_check_crontab').hide();
        }
    });
});
