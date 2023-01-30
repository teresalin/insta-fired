import os
import logging

from instagrapi import Client
from google.cloud.secretmanager import SecretManagerServiceClient


PROJECT = os.environ["PROJECT"]

def get_secret_version(project: str, secret_id: str, version_id: str = "latest"):
    secret_client = SecretManagerServiceClient()
    name = os.path.join('projects', project, 'secrets', secret_id, 'versions', version_id)
    response = secret_client.access_secret_version(name=name)
    return response.payload.data.decode('UTF-8')

def send_message():
    username = get_secret_version(PROJECT, 'insta-username')
    password = get_secret_version(PROJECT, 'insta-password')
    victim = get_secret_version(PROJECT, 'victim')

    cl = Client()
    cl.load_settings('session.json')
    cl.login(username, password)
    logging.info('Successfully logged in')

    send_to_user = cl.user_id_from_username(username=victim)
    cl.direct_send(text="How's that unemployment life?", user_ids=[send_to_user])
    logging.info(f'Success! Message sent to {victim}.')

def main(request):
    """Handles an HTTP request for a Cloud Scheduler job."""
    job_name = request.headers.get('X-Appengine-Cron-Job-Name')
    if job_name == 'my-daily-job':
        send_message()
    else:
        raise ValueError(f'Unexpected job name: {job_name}')

if __name__ == "__main__":
    main('data', 'context')
