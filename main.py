import os
import json
import logging

from instagrapi import Client

from google.cloud import kms
from google.cloud import storage
from google.cloud.secretmanager import SecretManagerServiceClient


PROJECT = os.environ["PROJECT"]
# TODO created google_secret_manager_secret_iam_member for each secret


def get_secret_version(project: str, secret_id: str, version_id: str = "latest"):
    secret_client = SecretManagerServiceClient()
    name = os.path.join('projects', project, 'secrets', secret_id, 'versions', version_id)
    print(name)
    response = secret_client.access_secret_version(name=name)
    return response.payload.data.decode('UTF-8')


def get_json_file_from_gcs(bucket_name, file_name):
    print(f'retrieving file {file_name}...')
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    file = bucket.blob(file_name)
    content = file.download_as_string()
    # return json.loads(content)
    return content


def decrypt_symmetric(project_id, location_id, key_ring_id, key_id, ciphertext):
    """
    Decrypt the ciphertext using the symmetric key

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        ciphertext (bytes): Encrypted bytes to decrypt.

    Returns:
        DecryptResponse: Response including plaintext.

    """

    print('decrypting text...')

    client = kms.KeyManagementServiceClient()

    # Build the key name.
    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

    # Optional, but recommended: compute ciphertext's CRC32C.
    # See crc32c() function defined below.
    ciphertext_crc32c = crc32c(ciphertext)

    # Call the API.
    decrypt_response = client.decrypt(
        request={'name': key_name, 'ciphertext': ciphertext, 'ciphertext_crc32c': ciphertext_crc32c})

    # Optional, but recommended: perform integrity verification on decrypt_response.
    # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    # https://cloud.google.com/kms/docs/data-integrity-guidelines
    if not decrypt_response.plaintext_crc32c == crc32c(decrypt_response.plaintext):
        raise Exception('The response received from the server was corrupted in-transit.')
    # End integrity verification

    print('Plaintext: {}'.format(decrypt_response.plaintext))
    return decrypt_response


def crc32c(data):
    """
    Calculates the CRC32C checksum of the provided data.
    Args:
        data: the bytes over which the checksum should be calculated.
    Returns:
        An int representing the CRC32C checksum of the provided bytes.
    """
    import crcmod
    import six
    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun('crc-32c')
    return crc32c_fun(six.ensure_binary(data))


def send_message():
    username = get_secret_version(PROJECT, 'insta-username')
    password = get_secret_version(PROJECT, 'insta-password')
    victim = get_secret_version(PROJECT, 'victim')

    cl = Client()
    encrypted_text = get_json_file_from_gcs('gcf-sources-956792429061-us-west2', 'session.json.encrypted')
    decrypted_text = decrypt_symmetric(PROJECT, 'us', 'my-key-ring', 'my-crypto-key', encrypted_text)
    print(f'decrypted text:\n{decrypted_text}')
    # cl.load_settings('session.json')
    cl.login(username, password)
    logging.info('Successfully logged in')

    # send_to_user = cl.user_id_from_username(username=victim)
    # cl.direct_send(text="How's that unemployment life?", user_ids=[send_to_user])
    # logging.info(f'Success! Message sent to {victim}.')


def main(request):
    """Handles an HTTP request for a Cloud Scheduler job."""
    job_name = request.headers.get('X-Appengine-Cron-Job-Name')
    if job_name == 'my-daily-job':
        send_message()
    else:
        raise ValueError(f'Unexpected job name: {job_name}')

# if __name__ == "__main__":
#     main('data', 'context')


def main():
    send_message()

if __name__ == "__main__":
    main()

