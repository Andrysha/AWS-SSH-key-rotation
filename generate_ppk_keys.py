import os
import json
import boto3
import paramiko
import subprocess

def retrieve_ssh_users(s3_ref):
    """ Function to retrieve users that will have their SSH keys rotated """

    # Retrieve users
    data = s3_ref.select_object_content(
        Bucket='bm-prod-ssh-keys',
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
    """ Lambda handler function to generate putty private key """

    s3 = boto3.client('s3')
    users = retrieve_ssh_users(s3)

    for user in users:
        s3.download_file('bm-prod-ssh-keys', '{}/prod_nat01_{}'.format(
            user['aws_username'], user['linux_username']), '/tmp/id_rsa')
        subprocess.run(['./puttygen', '/tmp/id_rsa', '-o', '/tmp/id_rsa.ppk',
                '-O', 'private'])
        s3.upload_file('/tmp/id_rsa.ppk', 'bm-prod-ssh-keys',
            '{}/prod_nat01_{}.ppk'.format(user['aws_username'],
            user['linux_username']))

    # Clean up lambda container
    os.remove('/tmp/id_rsa')
    os.remove('/tmp/id_rsa.ppk')
