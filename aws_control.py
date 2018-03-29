import sys
import boto.ec2

def map_elastic_ips(key, secret):
    conn = boto.ec2.connect_to_region("us-east-2",\
            aws_access_key_id=key,\
            aws_secret_access_key=secret)
    
    reservations = conn.get_all_reservations()
    instance_ids = [instance.id for r in reservations for instance in r.instances ]
    allocation_ids = [ads.allocation_id for ads in conn.get_all_addresses()]

    if len(instance_ids) != len(allocation_ids):
        print "Number of instances is not equal to number of elastic ips"
    else:
        for instance, ip in zip(instance_ids, allocation_ids):
            print '{} -> {}'.format(instance, ip)
            conn.associate_address(instance_id=instance, allocation_id=ip)

if __name__ == "__main__":
    key = sys.argv[1]
    secret = sys.argv[2]
    map_elastic_ips(key, secret)
