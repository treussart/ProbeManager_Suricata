from celery import task
from celery.utils.log import get_task_logger
from home.models import Probe, Job
import importlib
from home.utils import send_notification
import traceback


logger = get_task_logger(__name__)


@task
def deploy_rules(probe_name):
    response_deploy_rules = dict()
    job = Job.create_job('deploy_rules', probe_name)
    probe = Probe.get_by_name(probe_name)
    if probe is None:
        job.update_job("Error - probe is None - param id not set : " + str(probe_name), 'Error')
        return {"message": "Error - probe is None - param id not set : " + str(probe_name)}
    my_class = getattr(importlib.import_module(probe.type.lower() + ".models"), probe.type)
    probe = my_class.get_by_name(probe_name)
    try:
        response_tests = probe.test_rules()
        test_pcap = True
        errors = list()
        for pcaptest in probe.pcaptestsuricata_set.all():
            response_pcap_test = pcaptest.test()
            if not response_pcap_test['status']:
                test_pcap = False
                errors.append(str(pcaptest) + " : " + str(response_pcap_test['errors']))

        if probe.secure_deployment:
            if not response_tests['status']:
                job.update_job('Error during the rules test', 'Error')
                return {"message": "Error during the rules test for probe " + str(probe.name)}
            elif not test_pcap:
                job.update_job('Test pcap failed ! ', 'Error')
                return {"message": "Error during the pcap test for probe " + str(probe.name)}
        if not response_tests['status']:
            job.update_job('Error during the rules test: ' + str(response_tests['errors']), 'Error')
        elif not test_pcap:
            job.update_job('Error during the pcap test: ', 'Error')
        else:
            response_deploy_rules = probe.deploy_rules()
            response_reload = probe.reload()
            if response_deploy_rules and response_reload:
                job.update_job('Deployed rules successfully', 'Completed')
            else:
                job.update_job('Error during the rules deployed', 'Error')
            logger.info("task - deploy_rules : " + str(probe_name) + " - " + str(response_deploy_rules) + " - " + str(response_reload))
    except Exception as e:
        logger.error(e.__str__())
        logger.error(traceback.print_exc())
        job.update_job(e.__str__(), 'Error')
        send_notification("Probe " + str(probe.name), e.__str__())
        return {"message": "Error for probe " + str(probe.name) + " to deploy rules", "exception": e.__str__()}
    send_notification("Probe " + str(probe.name), "deployed rules successfully")
