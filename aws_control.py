import argparse
from botocore.exceptions import ClientError
import boto3
import json
import time

def release_elastic_ips(ec2):
    resp = ec2.describe_addresses()

    addresses = resp['Addresses']
    for add in addresses:
        try:
            ec2.release_address(AllocationId=add['AllocationId'])
            print('{} released'.format(add['AllocationId']))
        except ClientError as e:
            print(e)

def list_ips(ec2):
    resp = ec2.describe_addresses()

    addresses = resp['Addresses']
    if len(addresses) == 0:
        print('No ip found')

    for add in addresses:
        print('PublicIp: ', add['PublicIp'])

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
    if len(ids) > 0:
        print('Instances with ids - {} will be terminated...'.format(ids))
        ec2.terminate_instances(InstanceIds=ids)
    else:
        print("No running instance")

def cancel_fleet_requests(ec2):
    resp = ec2.describe_spot_fleet_requests()
    configs = resp['SpotFleetRequestConfigs']
    ids = []
    for config in configs:
        if config['SpotFleetRequestState'] == 'active':
            ids.append(config['SpotFleetRequestId'])

    if len(ids) > 0:
        print('Requests with {} ids will be cancelled'.format(ids))
        ec2.cancel_spot_fleet_requests(SpotFleetRequestIds=ids, TerminateInstances=True)
    else:
        print("No active request")

def fleet_request(ec2, configf, count, val_from="", val_until=""):
    with open(configf) as f:
        config = json.loads(f.read())
    if count > 0:
        config['TargetCapacity'] = count
    if not val_from == "":
        config['ValidFrom'] = val_from
    if not val_until == "":
        config['ValidUntil'] = val_until
    
    resp = ec2.request_spot_fleet(SpotFleetRequestConfig=config)
    check = 0
    filled = False

    while check < 15:
        r = ec2.describe_spot_fleet_instances(SpotFleetRequestId=resp['SpotFleetRequestId'])
        if len(r['ActiveInstances']) == config['TargetCapacity']:
            filled = True
            break
        time.sleep(10)
        check = check + 1
    
    if filled:
        print('Request has been fulfilled')
    else:
        print('There might be a problem')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fleet_request", default=False, action="store_true",
                        help="make spot fleet request")
    #launch related flags
    parser.add_argument("--count", default=0, type=int,
                        help="number of spot instances")
    parser.add_argument("--config", default="config.json",
                        help="launch template for the spot requests")
    parser.add_argument("--ValidFrom", default="",
                        help="if specified use this datetime")
    parser.add_argument("--ValidUntil", default="",
                        help="if specified use this datetime")

    #end of launch related flags
    parser.add_argument("--release_elastic_ips", default=False, action="store_true",
                        help="release all elastic ips")
    parser.add_argument("--map_elastic_ips", default=False, action="store_true",
                        help="map elastic ips to the running instances. if new ips are required they will be generated")
    parser.add_argument("--list_instances", default=False, action="store_true",
                        help="list instances and their status")
    parser.add_argument("--terminate_instances", default=False, action="store_true",
                        help="terminate all running instances")
    parser.add_argument("--cancel_fleet", default=False, action="store_true",
                        help="cancel all fleet requests")
    parser.add_argument("--list_elastic_ips", default=False, action="store_true",
                        help="cancel all fleet requests")

    args = parser.parse_args()

    ec2 = boto3.client('ec2')

    if args.fleet_request:
        fleet_request(ec2, args.config, args.count, val_from=args.ValidFrom, val_until=args.ValidUntil)
    elif args.release_elastic_ips:
        release_elastic_ips(ec2)
    elif args.map_elastic_ips:
        map_elastic_ips(ec2)
    elif args.list_instances:
        list_instances(ec2)
    elif args.terminate_instances:
        terminate_instances(ec2)
    elif args.cancel_fleet:
        cancel_fleet_requests(ec2)
    elif args.list_elastic_ips:
        list_ips(ec2)
