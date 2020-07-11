import os
import json
import boto3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key():
    """ Function to generate RSA public and private key pair """

    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048)

    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())

    public_key = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH)
    return private_key.decode('utf-8'), public_key.decode('utf-8')

def retrieve_ssh_users(s3_ref):
    """ Function to retrieve users that will have their SSH keys rotated """

    # Retrieve users
    data = s3_ref.select_object_content(
        Bucket='s3-bucket',
        Key='users.csv',
        ExpressionType='SQL',
        Expression='select * from s3object',
        InputSerialization={'CSV': {'FileHeaderInfo': 'USE',}},
        OutputSerialization={'JSON':{}}
    )

    # Clean retrieved data
    user_list = []
    for obj in data['Payload']:
        if 'Records' in obj:
            users = obj['Records']['Payload'].decode('utf-8')
            users = users.split('\n')
            for user in users[:-1]:
                temp = json.loads(user)
                for key, value in temp.items():
                    keys = key.split(',')
                    values = value.split(',')
                user_dict = {}
                for i in range(0, len(keys)):
                    user_dict[keys[i]] = values[i]
                user_list.append(user_dict)
    return user_list

def lambda_handler(event, context):
    """ Lambda handler function which will retrieve users from S3 csv file,
    generate RSA SSH keys and upload them to individual user bucket """

    s3 = boto3.client('s3')
    users = retrieve_ssh_users(s3)

    # Generate keys and upload to S3 bucket
    for user in users:
        priv_key, pub_key = generate_rsa_key()
        pub_key = pub_key + ' {}@remote'.format(user['linux_username'])
        with open('/tmp/id_rsa', 'w') as priv_key_file:
            priv_key_file.write(priv_key)

        with open('/tmp/id_rsa.pub', 'w') as pub_key_file:
            pub_key_file.write(pub_key)

        s3.upload_file('/tmp/id_rsa', 's3-bucket', '{}/jump_host_name_{}'.
            format(user['aws_username'], user['linux_username']))
        s3.upload_file('/tmp/id_rsa.pub', 's3-bucket',
            '{}/jump_host_name_{}.pub'.format(user['aws_username'],
            user['linux_username']))

    # Clean up lambda container
    os.remove('/tmp/id_rsa')
    os.remove('/tmp/id_rsa.pub')
