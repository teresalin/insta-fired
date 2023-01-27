import os

from instagrapi import Client


def send_message(request):
    cl = Client()
    cl.login(os.environ['ACCOUNT_USERNAME'], os.environ['ACCOUNT_PASSWORD'])

    send_to_user = cl.user_id_from_username(username="instagram name")
    cl.direct_send(text="How's that unemployment life?", user_ids=[send_to_user])

def main(request):
    """Handles an HTTP request for a Cloud Scheduler job."""
    job_name = request.headers.get('X-Appengine-Cron-Job-Name')
    if job_name == 'my-daily-job':
        send_message(request)
    else:
        raise ValueError(f'Unexpected job name: {job_name}')

if __name__ == "__main__":
    main('data', 'context')