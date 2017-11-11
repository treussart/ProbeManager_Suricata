django.jQuery(document).ready(function(){
    if(django.jQuery('#id_scheduled_enabled').is(':checked')){
        django.jQuery('.form-row.field-scheduled_crontab').show();
    } else {
        django.jQuery('.form-row.field-scheduled_crontab').hide();
    }
    django.jQuery('#id_scheduled_enabled').change(function(){
        if(django.jQuery('#id_scheduled_enabled').is(':checked')){
            django.jQuery('.form-row.field-scheduled_crontab').show();
        } else {
            django.jQuery('.form-row.field-scheduled_crontab').hide();
        }
    });
});