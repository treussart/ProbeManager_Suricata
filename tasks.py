import importlib

from celery import task
from celery.utils.log import get_task_logger

from core.models import Job, Probe
from core.notifications import send_notification
from suricata.models import RuleSetSuricata, IPReputation, CategoryReputation, SourceSuricata

logger = get_task_logger(__name__)


@task
def download_from_http(source_uri, rulesets_id=None):
    job = Job.create_job('download_from_http', source_uri)
    rulesets = list()
    if rulesets_id:
        for ruleset_id in rulesets_id:
            rulesets.append(RuleSetSuricata.get_by_id(ruleset_id))
    try:
        source = SourceSuricata.get_by_uri(source_uri)
        if source is None:
            job.update_job("Error - source is None : " + str(source_uri), 'Error')
            return {"message": "Error - source is None : " + str(source_uri)}
    except Exception as e:
        logger.exception("Error for source to upload")
        job.update_job(str(e), 'Error')
        return {"message": "Error for source to upload", "exception": str(e)}
    try:
        message = source.download_from_http(rulesets)
        job.update_job(message, 'Completed')
        logger.info("task - download_from_http : " + str(source_uri) + " - " + str(message))
    except Exception as e:
        logger.exception("Error for source to upload")
        job.update_job(str(e), 'Error')
        send_notification("Error for source " + str(source.uri), str(e))
        return {"message": "Error for source " + str(source.uri) + " to upload", "exception": str(e)}
    return {"message": "Source " + str(source.uri) + " uploaded successfully by HTTP", "upload_message": message}


@task
def deploy_reputation_list(probe_name):
    job = Job.create_job('deploy_reputation_list', probe_name)
    probe = Probe.get_by_name(probe_name)
    if probe is None:
        return {"message": "Error - probe is None - param id not set : " + str(probe_name)}
    my_class = getattr(importlib.import_module(probe.type.lower() + ".models"), probe.type)
    probe = my_class.get_by_name(probe_name)
    try:
        response_cat = CategoryReputation.deploy(probe)
        response_ip = IPReputation.deploy(probe)
        if response_cat['status'] and response_ip['status']:
            job.update_job(str(response_cat) + " - " + str(response_ip), 'Completed')
            logger.info("task - deploy_reputation_list : " + str(probe_name) + " - " +
                        str(response_cat) + " - " + str(response_ip))
        else:
            logger.error(str(response_cat) + " - " + str(response_ip))
            job.update_job(str(response_cat) + " - " + str(response_ip), 'Error')
            send_notification("Error during deploy reputation list for " +
                              str(probe.name), str(response_cat) + " - " + str(response_ip))
            return {"message": "Error for probe " + str(probe.name) + " to deploy reputation list",
                    "exception": str(response_cat) + " - " + str(response_ip)}
    except Exception as e:  # pragma: no cover
        logger.exception(str(e))
        job.update_job(str(e), 'Error')
        send_notification("Error during deploy reputation list for " + str(probe.name), str(e))
        return {"message": "Error for probe " + str(probe.name) + " to deploy reputation list", "exception": str(e)}
    return {"message": "Probe " + str(probe.name) + " deployed successfully reputation list"}


@task
def download_from_misp(source_uri, rulesets_id=None):
    job = Job.create_job('download_from_misp', source_uri)
    rulesets = list()
    if rulesets_id:
        for ruleset_id in rulesets_id:
            rulesets.append(RuleSetSuricata.get_by_id(ruleset_id))
    try:
        source = Source.get_by_uri(source_uri)
        if source is None:
            job.update_job("Error - source is None - param id not set : " + str(source_uri), 'Error')
            return {"message": "Error - source is None - param id not set : " + str(source_uri)}
        my_class = getattr(importlib.import_module(source.type.lower().split('source')[1] + ".models"), source.type)
        source = my_class.get_by_uri(source_uri)
    except Exception as e:
        logger.exception("Error for source to upload")
        job.update_job(str(e), 'Error')
        return {"message": "Error for source to upload", "exception": str(e)}
    try:
        message = source.download_from_misp(rulesets)
        job.update_job(message, 'Completed')
        logger.info("task - download_from_misp : " + str(source_uri) + " - " + str(message))
    except Exception as e:
        logger.exception("Error for source to upload")
        job.update_job(str(e), 'Error')
        send_notification("Error for source " + str(source.uri), str(e))
        return {"message": "Error for source " + str(source.uri) + " to download", "exception": str(e)}
    return {"message": "Source " + str(source.uri) + " uploaded successfully by MISP", "upload_message": message}
