import argparse
import boto3
from botocore.exceptions import ClientError

def release_elastic_ips(ec2):
    resp = ec2.describe_addresses()

    addresses = resp['Addresses']
    for add in addresses:
        try:
            response = ec2.release_address(AllocationId=add['AllocationId'])
            print('{} released'.format(add['AllocationId']))
        except ClientError as e:
            print(e)

def get_running_instances(ec2):
    resp = ec2.describe_instances()
    instance_ids = []
    reservations = resp['Reservations']
    for res in reservations:
        for ins in res['Instances']:
            if ins['State']['Name'] == 'running':
                instance_ids.append(ins['InstanceId'])
    return instance_ids


def map_elastic_ips(ec2):
    instance_ids = get_running_instances(ec2)
    resp = ec2.describe_addresses()
    addresses = resp['Addresses']
    required_new_addresses = len(instance_ids) - len(addresses)

    print('Need {} new elastic ips'.format(required_new_addresses))

    for _ in range(required_new_addresses):
        addresses.append(ec2.allocate_address())

    elastic_ips = [(add['AllocationId'], add['PublicIp']) for add in addresses]

    for ins_id, elastic_ip in zip(instance_ids, elastic_ips):
        response = ec2.associate_address(AllocationId=elastic_ip[0], InstanceId=ins_id)
        print('{} , {}, {}'.format(elastic_ip[0], elastic_ip[1], ins_id))

def list_instances(ec2):
    resp = ec2.describe_instances()
    reservations = resp['Reservations']
    for res in reservations:
        for ins in res['Instances']:
            print('Instance id: {}, Status: {}'.format(ins['InstanceId'], ins['State']['Name']))

def terminate_instances(ec2):
    ids = get_running_instances(ec2)
    print('Instances with ids - {} will be terminated...'.format(ids))
    ec2.terminate_instances(InstanceIds=ids)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", default=0, type=int,
            help="if request is greater than 0, then request spot instances")
    parser.add_argument("--release_elastic_ips", default=False, action="store_true",
            help="release all elastic ips")
    parser.add_argument("--map_elastic_ips", default=False, action="store_true",
            help="map elastic ips to the running instances. if new ips are required they will be generated")
    parser.add_argument("--list_instances", default=False, action="store_true",
            help="list instances and their status")
    parser.add_argument("--terminate_instances", default=False, action="store_true",
            help="terminate all running instances")

    args = parser.parse_args()

    ec2 = boto3.client('ec2')

    if args.request > 0:
        print("Nothing")
    elif args.release_elastic_ips:
        release_elastic_ips(ec2)
    elif args.map_elastic_ips:
        map_elastic_ips(ec2)
    elif args.list_instances:
        list_instances(ec2)
    elif args.terminate_instances:
        terminate_instances(ec2)
