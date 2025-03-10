import click
from datetime import datetime
import ipaddress
from subcommands.utils import make_sync
from utils import file as unicor_file_utils
from utils import time as unicor_time_utils
from utils import alert as unicor_alerting_utils
import logging
import hashlib
import jinja2
from datetime import datetime, timedelta
import time
import jsonlines
from pymisp import PyMISP
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)

def sha256_hash(text):
    sha256 = hashlib.sha256()
    sha256.update(text.encode('utf-8'))
    return sha256.hexdigest()


def if_alert_exists(alerts_database, alert):
    with open(alerts_database, 'r') as file:
        hashes = set(file.read().splitlines())
    return alert in hashes

@click.command(help="Send alerts to pre-defined destinations like Slack")
@click.argument(
    'files',
    nargs=-1,
    type=click.Path(
        file_okay=True,
        dir_okay=True,
        readable=True,
        allow_dash=True
    )
)
@click.option(
    'logging_level',
    '--logging',
    type=click.Choice(['INFO','WARN','DEBUG','ERROR']),
    default="INFO"
)

@click.pass_context
def alert(ctx,
    **kwargs):
    alerts_counter = 0
    alerting_config = ctx.obj['CONFIG']['alerting']
    correlation_config = ctx.obj['CONFIG']['correlation']
    alerts_database = correlation_config['alerts_database']
    alerts_database_max_size = correlation_config['alerts_database_max_size']
    max_alerts_counter = alerting_config['max_alerts']
    if not kwargs.get('files'):
        files = [correlation_config['output_dir']]
    else:
        files = kwargs.get('files')
        
    # Iterating through the file or the directory
    for file in files:
        file_path = Path(file)
        file_paths = [file_path] if file_path.is_file() else file_path.rglob('*')
        for file_path in file_paths:      
            # Processing each file in the directory
            if file_path.is_file():
                alerts, _ =  unicor_file_utils.read_file(file_path, delete_after_read=False)
                logger.info("{} alerts to be processed".format(len(alerts)))  
                # Processing each alert in each file
                if alerts:
                    try:
                        # Going through each of the alerts
                        for match in alerts:
                                # Making a string from the timestamp that should cover a 24h window
                                if match.get('detections'): # In case we have multiple detection, we take the first
                                    first_timestamp = min(d["timestamp_rfc3339ns"] for d in match["detections"])
                                    dt = datetime.strptime(first_timestamp[:26], "%Y-%m-%dT%H:%M:%S.%f")
                                else: # We have a single detection
                                    dt = datetime.strptime(match['timestamp'][:26], "%Y-%m-%dT%H:%M:%S.%f")
                                epoch_time = int(time.mktime(dt.timetuple()))
                                truncated_timestamp = epoch_time - (epoch_time % 86400)
                                
                                # First, make sure we are not about to create a duplicate alert 
                                if match.get('detections'): # In case we have multiple detection, we take the first
                                    alert_pattern  =  sha256_hash(match["detections"][0]["detection"] + match['ioc'] + str(truncated_timestamp))
                                else: # We have a single detection
                                    alert_pattern  =  sha256_hash(match['detection'] + match['ioc'] + str(truncated_timestamp))
                                if if_alert_exists(alerts_database, alert_pattern):
                                    logger.debug("Redundant alert, skipping: {}".format(alert_pattern))
                                    continue 
                                
                                # At this stage, each remaining alert needs to be sent, if it is under the threshold!
                                                        
                                if alerts_counter < max_alerts_counter:
                                    logger.debug("Sending an alert for: {}".format(alert_pattern))
                                    if alerts_counter == max_alerts_counter - 1:
                                        if match.get('detections'): # In case we have multiple detections
                                            match["detections"][-1]["detection"] += "\n\n*WARNING*: TOO MANY ALERTS, NOT SENDING MORE, CHECK UNICOR LOGS."
                                        else:  #We have a single detection            
                                            match['detection'] += "\n\n*WARNING*: TOO MANY ALERTS, NOT SENDING MORE, CHECK UNICOR LOGS."
                                    
                                    for alert_type, alert_conf in ctx.obj['CONFIG']['alerting'].items():
                                        logger.debug("Alerting via {}".format(alert_type))
                                        # Preparing and send alerts for specific destinations
                                        if alert_type == "messaging_webhook":
                                            unicor_alerting_utils.messaging_webhook_alerts(match, alerting_config['messaging_webhook'], alert_pattern, alerts_database, alerts_database_max_size, alert_type)
                                        if alert_type == "telegram":
                                            unicor_alerting_utils.telegram_alerts(match, alerting_config['telegram'], alert_pattern, alerts_database, alerts_database_max_size, alert_type)
                                        if alert_type == "email":           
                                            unicor_alerting_utils.email_alerts(match, alerting_config['email'], summary=False)
                                if alerts_counter == max_alerts_counter:
                                    logger.warning("Too many alerts to be sent, sent only {}".format(max_alerts_counter))
                                alerts_counter += 1

                                # Here we need to catch an exception.
                                # If the request worked, then register the alert in our "database" to avoir duplicate alerts
                                #register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)

                    except Exception as e:  # Capture specific error details        
                        logger.error("Failed to parse {}, skipping. Error: {}".format(file, str(e)))
                        continue
                logger.debug("Deleting content of: {}".format(file_path))
                with open(file_path, 'w') as file:
                    file.write("")  # Write an empty string to the file and automatically close it
                logger.debug("Deleting content of {}".format(file_path))
                with open(file_path, 'w') as file:
                    file.write("")  # Write an empty string to the file and automatically close it

   # if not len(pending_alerts):
    #    logger.info("No alert to be sent.")


