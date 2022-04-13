import json
import boto3
import os
import concurrent.futures

from botocore.exceptions import ClientError

AWS_BUCKETS = os.environ.get('AWS_BUCKETS', None)
AWS_BUCKETS_FILE = os.environ.get('AWS_BUCKETS_FILE', None)

session = boto3.Session(profile_name=os.environ.get('AWS_PROFILE'), aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'), aws_session_token=os.environ.get('AWS_SESSION_TOKEN'))
s3 = session.client('s3', region_name='us-east-1')

def update_bucket_sse(bucket):
    try:
        print('[{}] Enabling SSE with {}...'.format(bucket['bucket'], 'AWS Managed Key' if bucket['key'] == 'aws' else bucket['key']))
        sseRule = {
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': '{}'.format('AES256' if bucket['key'] == 'aws' else 'aws:kms')
                    }
                }
            ]
        }
        if bucket['key'] != 'aws':
            sseRule['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID'] = bucket['key']

        s3.put_bucket_encryption(
            Bucket=bucket['bucket'],
            ServerSideEncryptionConfiguration=sseRule
        )
        print('[{}] SSE enabled successfully with {}'.format(bucket['bucket'], 'AWS Managed Key' if bucket['key'] == 'aws' else bucket['key']))
        return {
            'status': 'ok',
            'bucket': bucket
        }
    except (Exception, ClientError) as ce:
        print('[{}] Failed to enable SSE with {}. Reason: {}'.format(bucket, 'AWS Managed Key' if bucket['key'] == 'aws' else bucket['key'], ce))
        return {
            'status': 'fail',
            'bucket': bucket
        }

def update_buckets_sse(buckets):
    with concurrent.futures.ThreadPoolExecutor(10) as executor:
        results = [executor.submit(update_bucket_sse, bucket) for bucket in buckets]

    appliedBuckets = []
    failedBuckets = []
    skippedBuckets = []
    try:
        for f in results:
            if f.result()['status'] == 'ok':
                appliedBuckets.append(f.result()['bucket'])
            elif f.result()['status'] == 'fail':
                failedBuckets.append(f.result()['bucket'])
            elif f.result()['status'] == 'skip':
                skippedBuckets.append(f.result()['bucket'])
    except Exception as e:
        print('Error: {}'.format(e))

    print('\nTotal bucket count: {}'.format(len(appliedBuckets) + len(failedBuckets) + len(skippedBuckets)))

    print('==========================')
    print('SSE enabled for {} bucket(s)'.format(len(appliedBuckets)))
    if len(appliedBuckets) > 0:
        print('> {}'.format('\n> '.join(['{} = {}'.format(b['bucket'], b['key']) for b in appliedBuckets])))
    print('==========================')

    print('==========================')
    print('SSE failed for {} bucket(s)'.format(len(failedBuckets)))
    if len(failedBuckets) > 0:
        print('> {}'.format('\n> '.join(['{} = {}'.format(b['bucket'], b['key']) for b in failedBuckets])))
    print('==========================')

    print('==========================')
    print('SSE skipped for {} bucket(s)'.format(len(skippedBuckets)))
    if len(skippedBuckets) > 0:
        print('> {}'.format('\n> '.join(['{} = {}'.format(b['bucket'], b['key']) for b in skippedBuckets])))
    print('==========================')

def print_help():
    return '''ERROR: Either AWS_BUCKETS or AWS_BUCKETS_FILE is required.

Usage: AWS_BUCKETS=all python3 s3-enable-sse.py

To enable SSE using AWS Managed Key for the bucket(s) pass AWS_BUCKETS variable with either of the following value:
- AWS_BUCKETS: bucket1 (Single bucket)
- AWS_BUCKETS: bucket1, bucket2, bucket10 (Multiple buckets)
- AWS_BUCKETS: all (All buckets)

To enable SSE using Customer Managed Key or a combination of different key type pass AWS_BUCKETS_FILE with file path as value:
- AWS_BUCKETS_FILE: buckets.json

=========================
buckets.json file format:
=========================
[
    {
        "bucket": "bucket1",
        "key": "aws"    # To use aws default managed key
    },
    {
        "bucket": "bucket2",
        "key": "kms_key_id or kms_kms_key_arn"    # To use customer managed key
    }
]

For AWS authentication please use the following variables:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_SESSION_TOKEN
- AWS_PROFILE
'''

if AWS_BUCKETS is None and AWS_BUCKETS_FILE is None:
    print_help()
elif AWS_BUCKETS is not None and AWS_BUCKETS_FILE is not None:
    print_help()
elif AWS_BUCKETS is not None:
    print('Preparing bucket(s)...', end=' ', flush=True)
    AWS_BUCKET_NAMES = []
    if AWS_BUCKETS.lower() == 'all':
        resp = s3.list_buckets()
        AWS_BUCKET_NAMES = [{'bucket': b['Name'], 'key': 'aws'} for b in resp['Buckets']]
    elif ',' in AWS_BUCKETS:
        AWS_BUCKET_NAMES = [{'bucket': r.strip(), 'key': 'aws'} for r in AWS_BUCKETS.split(',')]
    else:
        AWS_BUCKET_NAMES.append({
            'bucket': AWS_BUCKETS,
            'key': 'aws'
        })
    print('ok')
else:
    print('Loading bucket(s)...', end=' ', flush=True)
    AWS_BUCKET_NAMES = json.load(open(AWS_BUCKETS_FILE, 'r'))
    print('ok')

if len(AWS_BUCKET_NAMES) > 0:
    print('==============================================')
    print('SSE will be enabled for the following bucket(s): \n> {}'.format('\n> '.join(['{} = {}'.format(b['bucket'], b['key']) for b in AWS_BUCKET_NAMES])))
    print('==============================================')
    resp = input('Are you sure you want to continue (Y/n): ').lower()
    if resp == '' or resp == 'y':
        update_buckets_sse(AWS_BUCKET_NAMES)
    else:
        print('Exiting as per user input')
