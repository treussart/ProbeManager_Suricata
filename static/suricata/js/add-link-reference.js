django.jQuery(document).ready(function(){
    var value_ref = django.jQuery('#id_reference').val();
    django.jQuery('#id_reference').after( "&nbsp;&nbsp;&nbsp;<a href='http://" + value_ref + "' target='_blank'>" + value_ref + "</a>" );
});

django.jQuery(document).ready(function(){
    var value_ref = django.jQuery('#id_uri').val();
    django.jQuery('#id_uri').after( "&nbsp;&nbsp;&nbsp;<a href='http://" + value_ref + "' target='_blank'>" + value_ref + "</a>" );
});