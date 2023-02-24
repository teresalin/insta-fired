import os
import logging

from instagrapi import Client
from instagrapi.exceptions import LoginRequired

from google.cloud.secretmanager import SecretManagerServiceClient

logging.basicConfig(level=logging.INFO)


PROJECT = os.environ["PROJECT"]


def get_secret_version(project: str, secret_id: str, version_id: str = "latest"):
    secret_client = SecretManagerServiceClient()
    name = os.path.join('projects', project, 'secrets',
                        secret_id, 'versions', version_id)
    response = secret_client.access_secret_version(name=name)
    return response.payload.data.decode('UTF-8')


def send_message(request):
    username = get_secret_version(PROJECT, 'insta-username')
    password = get_secret_version(PROJECT, 'insta-password')
    victim = get_secret_version(PROJECT, 'victim')

    cl = Client()
    cl.login(username, password)

    try:
        account = cl.account_info()
        logging.info(f'Successfully logged in as {account.full_name}')
    except LoginRequired:
        cl.relogin()

    send_to_user = cl.user_id_from_username(username=victim)
    cl.direct_send(text="How's that unemployment life?",
                   user_ids=[send_to_user])
    logging.info(f'Success! Message sent to {victim}.')
