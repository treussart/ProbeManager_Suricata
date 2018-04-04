django.jQuery(document).ready(function(){
    var valueRef = django.jQuery("#id_reference").val();
    django.jQuery("#id_reference").after( "&nbsp;&nbsp;&nbsp;<a href='http://" + valueRef + "' target='_blank'>" + valueRef + "</a>" );
});

django.jQuery(document).ready(function(){
    var valueRef = django.jQuery("#id_uri").val();
    django.jQuery("#id_uri").after( "&nbsp;&nbsp;&nbsp;<a href='http://" + valueRef + "' target='_blank'>" + valueRef + "</a>" );
});
