import boto3
import os
import concurrent.futures

from botocore.exceptions import ClientError

AWS_REGIONS = os.environ.get('AWS_REGIONS', None)

session = boto3.Session(profile_name=os.environ.get('AWS_PROFILE'), aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'), aws_session_token=os.environ.get('AWS_SESSION_TOKEN'))

def delete_vpc(regionId, ec2Client):
    try:
        print('Fetching default VPC in {} region...'.format(regionId))
        resp = ec2Client.describe_vpcs(
            Filters=[
                {
                    'Name': 'is-default',
                    'Values': [
                        'true'
                    ]
                }
            ]
        )
        vpcId = resp['Vpcs'][0]['VpcId']
        print('Default VPC found in {} region. Id: {}'.format(regionId, vpcId))

        print('Fetching internet gateway associated with {}...'.format(vpcId))
        resp = ec2Client.describe_internet_gateways(
            Filters=[
                {
                    'Name': 'attachment.vpc-id',
                    'Values': [
                        vpcId,
                    ]
                },
            ]
        )
        if len(resp['InternetGateways']) > 0:
            igwId = resp['InternetGateways'][0]['InternetGatewayId']
            print('Detaching internet gateway {} associated with {}...'.format(igwId, vpcId))
            ec2Client.detach_internet_gateway(
                InternetGatewayId=igwId,
                VpcId=vpcId,
            )
            print('Internet gateway {} associated with {} detached'.format(igwId, vpcId))

            print('Deleting internet gateway {} associated with {}...'.format(igwId, vpcId))
            ec2Client.delete_internet_gateway(
                InternetGatewayId=igwId
            )
            print('Internet gateway {} associated with {} deleted'.format(igwId, vpcId))
        else:
            print('No internet gateway found in {}'.format(vpcId))

        print('Fetching subnets associated with {}...'.format(vpcId))
        resp = ec2Client.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        vpcId,
                    ]
                },
            ]
        )
        if len(resp['Subnets']) > 0:
            subnetIds = [s['SubnetId'] for s in resp['Subnets']]
            for sid in subnetIds:
                print('Deleting subnet {} associated with {}...'.format(sid, vpcId))
                ec2Client.delete_subnet(
                    SubnetId=sid
                )
                print('Subnet {} associated with {} deleted'.format(sid, vpcId))
        else:
            print('No subnets found in {}'.format(vpcId))

        print('Deleting default VPC {} in {} region...'.format(vpcId, regionId))
        ec2Client.delete_vpc(
            VpcId=vpcId
        )
        print('Vpc {} in {} region deleted successfully'.format(vpcId, regionId))
        return {
            'status': 'success',
            'id': vpcId,
            'region': regionId
        }
    except IndexError:
        print('Default VPC not found in {} region'.format(regionId))
        return {
            'status': 'missing',
            'region': regionId
        }
    except (Exception, ClientError) as e:
        print('Error: Failed to delete VPC in {} region. Reason: {}'.format(regionId, e))
        return {
            'status': 'failed',
            'id': vpcId,
            'region': regionId
        }

def delete_vpcs(regionIds):
    with concurrent.futures.ThreadPoolExecutor(10) as executor:
        results = [executor.submit(delete_vpc, region, session.client('ec2', region_name=region)) for region in regionIds]

    vpcStatus = {
        'success': [],
        'failed': [],
        'missing': []
    }
    for f in concurrent.futures.as_completed(results):
        if f.result()['status'] == 'success':
            vpcStatus['success'].append({
                'id': f.result()['id'],
                'region': f.result()['region']
            })
        elif f.result()['status'] == 'failed':
            vpcStatus['failed'].append({
                'id': f.result()['id'],
                'region': f.result()['region']
            })
        else:
            vpcStatus['missing'].append(f.result()['region'])

    print('\nVpc(s) successfuly deleted: {}'.format(len(vpcStatus['success'])))
    if len(vpcStatus['success']) > 0:
        print('===========================')
        print('VPC\t\tRegion')
        print('===========================')
        for v in vpcStatus['success']:
            print('{}\t{}'.format(v['id'], v['region']))

    print('\nVpc(s) failed to delete: {}'.format(len(vpcStatus['failed'])))
    if len(vpcStatus['failed']) > 0:
        print('===========================')
        print('VPC\t\tRegion')
        print('===========================')

        for v in vpcStatus['failed']:
            print('{}\t{}'.format(v['id'], v['region']))

    print('\nRegion(s) missing default VPC: {} ({})'.format(len(vpcStatus['missing']), ', '.join(vpcStatus['missing'])))

if AWS_REGIONS is None:
    print('''Error: AWS_REGIONS cannot be blank.

To delete default VPC(s) the value for AWS_REGIONS variable needs to be either of the following:
- Single region: us-east-1
- Multiple regions: us-east-1, us-east-2, eu-west-2
- All regions: all

For AWS authentication please use the following variables:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_SESSION_TOKEN
- AWS_PROFILE''')
    print('''
Usage: AWS_REGIONS=all python3 delete-default-vpc.py
''')
else:
    print('Preparing region(s)...', end=' ', flush=True)
    if AWS_REGIONS.lower() == 'all':
        ec2 = session.client('ec2', region_name='us-east-1')
        resp = ec2.describe_regions(AllRegions=False)
        AWS_REGION_IDS = [r['RegionName'] for r in resp['Regions']]
    elif ',' in AWS_REGIONS:
        AWS_REGION_IDS = [r.strip() for r in AWS_REGIONS.split(',')]
    else:
        AWS_REGION_IDS = [AWS_REGIONS]
    print('ok')

    print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    print('Default VPC in following region(s) will be deleted if they exist: \n> {}'.format('\n> '.join(AWS_REGION_IDS)))
    print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    resp = input('Are you sure you want to continue (Y/n): ').lower()
    if resp == '' or resp == 'y':
        delete_vpcs(AWS_REGION_IDS)
    else:
        print('Exiting as per user input')
