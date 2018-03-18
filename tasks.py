import importlib
import traceback

from core.models import Job
from core.notifications import send_notification
from rules.models import Source
from suricata.models import RuleSetSuricata

from celery import task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@task
def upload_url_http(source_uri, rulesets_id=None):
    job = Job.create_job('upload_url_http', source_uri)
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
        message = source.upload(rulesets)
        job.update_job(message, 'Completed')
        logger.info("task - upload_url_http : " + str(source_uri) + " - " + str(message))
    except Exception as e:
        print(traceback.print_exc())
        logger.exception("Error for source to upload")
        job.update_job(str(e), 'Error')
        send_notification("Error for source " + str(source.uri), str(e))
        return {"message": "Error for source " + str(source.uri) + " to upload", "exception": str(e)}
    return {"message": "Source " + str(source.uri) + " uploaded successfully by HTTP", "upload_message": message}
