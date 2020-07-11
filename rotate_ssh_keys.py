import os
import io
import ssl
import json
import boto3
import smtplib
import paramiko
import subprocess

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from botocore.exceptions import ClientError

def get_ssh_users(s3_ref):
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

def get_private_key():
    """ Function to retrieve admin's private key """

    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId='secret')
    except ClientError as error:
        raise error
    else:
        secret = response['SecretString']
        priv_key_obj = json.loads(secret)
        # Convert private key string to file in memory
        priv_key = io.StringIO()
        priv_key.write(priv_key_obj['key'])
        priv_key.seek(0)
        private_key = paramiko.RSAKey.from_private_key(priv_key)
        return private_key

def get_public_key(user):
    """ Function to retrieve user's public key """

    s3 = boto3.resource('s3')
    obj = s3.Object('s3-bucket', '{}/jump_host_name_{}.pub'.format(
        user['aws_username'], user['linux_username']))
    public_key = obj.get()['Body'].read().decode('utf-8')
    return public_key

def create_ssh_client(hostname, username, private_key):
    """ Function to create ssh tunnel with paramiko """

    # Establish SSH Connection
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=hostname, username=username, pkey=private_key)
    return client

def send_email(user):
    """ Function to notify user about SSH key rotation via email """

    SMTP_PORT = 587
    SMTP_SERVER = 'email-smtp.us-east-1.amazonaws.com'
    SENDER = 'no-reply@yourdomain.com'

    # Retrieve SMTP credentials
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId='smtp')
    except ClientError as error:
        raise error
    else:
        secret = response['SecretString']
        secret_obj = json.loads(secret)
        smtp_username = secret_obj['username']
        smtp_password = secret_obj['password']

    # Generate to, from and subject
    message = MIMEMultipart('mixed')
    message['Subject'] = 'SSH key rotation - {}'.format(
        user['linux_username'])
    message['From'] = SENDER
    message['To'] = user['email']

    # Generate body of the email
    html = '''
    <html>
        <body>
            <p>New SSH Key pair for user {0} has been generated and
            available for download from AWS S3.</p>
            <span>To retrieve newly generated private key:</span>
            <ol type="1">
                <li>Login to AWS console.</li>
                <li>Navigate to S3 service.</li>
                <li>Download jump_host_name_{0} file  from s3-bucket/{1}
                S3 bucket.</li>
                <li>Modify DBeaver benchmark production connection to use
                newly downloaded key. See attachment for detailed
                instructions.</li>
            </ol>
            <p>For any questions or issues please contact.</p>
         </body>
    </html>'''.format(user['linux_username'], user['aws_username'])
    body = MIMEText(html, 'html')
    message.attach(body)

    # Add instructions attachment
    s3 = boto3.client('s3')
    s3.download_file('s3-bucket', 'ssh_tunnel_settings.pdf',
        '/tmp/ssh_tunnel_settings.pdf')
    filename='/tmp/ssh_tunnel_settings.pdf'
    with open(filename, 'rb') as pdf:
        attachment = MIMEApplication(pdf.read())
        #attachment = MIMEApplication(pdf.read(), Name='{}'.format(filename))
    attachment.add_header('Content-Disposition', 'attachment',
        filename=filename.lstrip('/tmp'))
    message.attach(attachment)

    # Send email
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_username, smtp_password)
        server.sendmail(SENDER, user['email'], message.as_string())

def lambda_handler(event, context):
    """ Lambda handler function to generate putty private key """

    # Establish SSH session to jump_host_name
    private_key = get_private_key()
    ssh = create_ssh_client('jump_host_name', 'username', private_key)

    s3 = boto3.client('s3')
    users = get_ssh_users(s3)
    for user in users:
        public_key = get_public_key(user)
        grep_cmd = ('sudo su - {0} -c "grep -q {0}@remote /home/{0}/.ssh/'
            'authorized_keys && echo 1"'.format(user['linux_username']))
        stdin, stdout, stderr = ssh.exec_command(grep_cmd)
        # if old key exists, replace with new one
        if (stdout.read().decode('utf-8').rstrip() == '1'):
            sed = ('\"sed -i \'/{0}@remote/ c\\{1}\' /home/{0}/.ssh/'
                'authorized_keys\"'.format(user['linux_username'], public_key))
            sed_cmd = 'sudo su - {} -c {}'.format(user['linux_username'], sed)
            ssh.exec_command(sed_cmd)
        # if old key is not present, wipe file and add new public key
        else:
            echo_cmd = ('sudo su - {0} -c "echo {1} > /home/{0}/.ssh/'
                'authorized_keys"'.format(user['linux_username'], public_key))
            ssh.exec_command(echo_cmd)
            chmod_cmd = ('sudo su - {0} -c "chmod 600 /home/{0}/.ssh/'
                'authorized_keys"'.format(user['linux_username']))
            ssh.exec_command(chmod_cmd)
        send_email(user)
    # Close SSH session to jump_host_name
    ssh.close()

    # Remove instructions file
    os.remove('/tmp/ssh_tunnel_settings.pdf')
