import boto3

def check_s3_public_access():
    """
    PCI-DSS Requirement 1.3 / 7.1 (restrict access to cardholder data)
    Checks all S3 buckets for public access via block-public-access settings
    or public bucket policy.
    """
    s3 = boto3.client('s3')
    results = []

    buckets = s3.list_buckets()['Buckets']
    buckets = [b for b in buckets if b['Name'].startswith('pcidss-')]

    for bucket in buckets:
        bucket_name = bucket['Name']

        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            config = pab['PublicAccessBlockConfiguration']
            is_blocked = all(config.values())
        except s3.exceptions.ClientError:
            
            is_blocked = False

        if not is_blocked:
            results.append({
                'resource': bucket_name,
                'status': 'FAIL',
                'detail': 'Public access block is not fully enabled',
                'pci_requirement': '1.3 / 7.1'
            })
        else:
            results.append({
                'resource': bucket_name,
                'status': 'PASS',
                'detail': 'Public access block fully enabled',
                'pci_requirement': '1.3 / 7.1'
            })

    return results




def check_s3_encryption():
    """
    PCI-DSS Requirement 3.4 (render cardholder data unreadable)
    Checks all project S3 buckets for server-side encryption.
    """
    s3 = boto3.client('s3')
    results = []

    buckets = s3.list_buckets()['Buckets']
    buckets = [b for b in buckets if b['Name'].startswith('pcidss-')]

    for bucket in buckets:
        bucket_name = bucket['Name']

        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            is_encrypted = len(rules) > 0
        except s3.exceptions.ClientError:
            
            is_encrypted = False

        if not is_encrypted:
            results.append({
                'resource': bucket_name,
                'status': 'FAIL',
                'detail': 'No server-side encryption configured',
                'pci_requirement': '3.4'
            })
        else:
            results.append({
                'resource': bucket_name,
                'status': 'PASS',
                'detail': 'Server-side encryption enabled',
                'pci_requirement': '3.4'
            })

    return results


def check_ebs_encryption():
    """
    PCI-DSS Requirement 3.4 (render cardholder data unreadable)
    Checks all EBS volumes for encryption at rest.
    """
    ec2 = boto3.client('ec2')
    results = []

    volumes = ec2.describe_volumes(
        Filters=[{'Name': 'tag:Project', 'Values': ['pcidss-scanner']}]
    )['Volumes']

    for volume in volumes:
        volume_id = volume['VolumeId']
        is_encrypted = volume['Encrypted']

        if not is_encrypted:
            results.append({
                'resource': volume_id,
                'status': 'FAIL',
                'detail': 'EBS volume is not encrypted',
                'pci_requirement': '3.4'
            })
        else:
            results.append({
                'resource': volume_id,
                'status': 'PASS',
                'detail': 'EBS volume is encrypted',
                'pci_requirement': '3.4'
            })

    return results

def check_security_groups():
    """
    PCI-DSS Requirement 1.2 / 1.3 (restrict inbound/outbound traffic)
    Checks security groups for high-risk ports open to 0.0.0.0/0.
    """
    ec2 = boto3.client('ec2')
    results = []

    risky_ports = {22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL'}

    security_groups = ec2.describe_security_groups(
        Filters=[{'Name': 'tag:Project', 'Values': ['pcidss-scanner']}]
    )['SecurityGroups']

    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        open_ports = []

        for rule in sg['IpPermissions']:
            from_port = rule.get('FromPort')
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0' and from_port in risky_ports:
                    open_ports.append(f"{risky_ports[from_port]} ({from_port})")

        if open_ports:
            results.append({
                'resource': f"{sg_name} ({sg_id})",
                'status': 'FAIL',
                'detail': f"Open to 0.0.0.0/0 on: {', '.join(open_ports)}",
                'pci_requirement': '1.2 / 1.3'
            })
        else:
            results.append({
                'resource': f"{sg_name} ({sg_id})",
                'status': 'PASS',
                'detail': 'No high-risk ports open to the internet',
                'pci_requirement': '1.2 / 1.3'
            })

    return results


def check_iam_mfa():
    """
    PCI-DSS Requirement 8.3 (multi-factor authentication)
    Checks all IAM users for MFA device enrollment.
    """
    iam = boto3.client('iam')
    results = []

    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']

        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        has_mfa = len(mfa_devices) > 0

        if not has_mfa:
            results.append({
                'resource': username,
                'status': 'FAIL',
                'detail': 'No MFA device enrolled',
                'pci_requirement': '8.3'
            })
        else:
            results.append({
                'resource': username,
                'status': 'PASS',
                'detail': 'MFA device enrolled',
                'pci_requirement': '8.3'
            })

    return results


from datetime import datetime, timezone

def check_iam_key_age():
    """
    PCI-DSS Requirement 8.2.4 (periodic credential rotation)
    Checks all IAM users' access keys for age over 90 days.
    """
    iam = boto3.client('iam')
    results = []

    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

        if not keys:
            results.append({
                'resource': username,
                'status': 'PASS',
                'detail': 'No access keys present',
                'pci_requirement': '8.2.4'
            })
            continue

        for key in keys:
            key_id = key['AccessKeyId']
            masked_key =  '..........' + key_id[-4:]
            create_date = key['CreateDate']
            age_days = (datetime.now(timezone.utc) - create_date).days

            if age_days > 90:
                results.append({
                    'resource': f"{username} ({masked_key})",
                    'status': 'FAIL',
                    'detail': f'Access key is {age_days} days old (exceeds 90-day limit)',
                    'pci_requirement': '8.2.4'
                })
            else:
                results.append({
                    'resource': f"{username} ({masked_key})",
                    'status': 'PASS',
                    'detail': f'Access key is {age_days} days old',
                    'pci_requirement': '8.2.4'
                })

    return results


def check_rds_security():
    """
    PCI-DSS Requirement 3.4 (encryption) and 1.3 (restrict public access)
    Checks all RDS instances for encryption and public accessibility.
    """
    rds = boto3.client('rds')
    results = []

    instances = rds.describe_db_instances()['DBInstances']

    if not instances:
        results.append({
            'resource': 'N/A',
            'status': 'PASS',
            'detail': 'No RDS instances found in this account/region',
            'pci_requirement': '3.4 / 1.3'
        })
        return results

    for instance in instances:
        db_id = instance['DBInstanceIdentifier']
        is_encrypted = instance['StorageEncrypted']
        is_public = instance['PubliclyAccessible']

        if not is_encrypted:
            results.append({
                'resource': db_id,
                'status': 'FAIL',
                'detail': 'RDS storage is not encrypted',
                'pci_requirement': '3.4'
            })
        else:
            results.append({
                'resource': db_id,
                'status': 'PASS',
                'detail': 'RDS storage is encrypted',
                'pci_requirement': '3.4'
            })

        if is_public:
            results.append({
                'resource': db_id,
                'status': 'FAIL',
                'detail': 'RDS instance is publicly accessible',
                'pci_requirement': '1.3'
            })
        else:
            results.append({
                'resource': db_id,
                'status': 'PASS',
                'detail': 'RDS instance is not publicly accessible',
                'pci_requirement': '1.3'
            })

    return results


def check_cloudtrail():
    """
    PCI-DSS Requirement 10.1 / 10.2 (audit trails for system access)
    Checks whether CloudTrail is enabled with multi-region logging.
    """
    cloudtrail = boto3.client('cloudtrail')
    results = []

    trails = cloudtrail.describe_trails()['trailList']

    if not trails:
        results.append({
            'resource': 'N/A',
            'status': 'FAIL',
            'detail': 'No CloudTrail trails configured',
            'pci_requirement': '10.1 / 10.2'
        })
        return results

    for trail in trails:
        trail_name = trail['Name']
        is_multi_region = trail.get('IsMultiRegionTrail', False)

        status = cloudtrail.get_trail_status(Name=trail_name)
        is_logging = status.get('IsLogging', False)

        if not is_logging:
            results.append({
                'resource': trail_name,
                'status': 'FAIL',
                'detail': 'Trail exists but logging is not active',
                'pci_requirement': '10.1 / 10.2'
            })
        elif not is_multi_region:
            results.append({
                'resource': trail_name,
                'status': 'FAIL',
                'detail': 'Trail is logging but not multi-region',
                'pci_requirement': '10.1 / 10.2'
            })
        else:
            results.append({
                'resource': trail_name,
                'status': 'PASS',
                'detail': 'Trail is active and multi-region',
                'pci_requirement': '10.1 / 10.2'
            })

    return results


def check_vpc_flow_logs():
    """
    PCI-DSS Requirement 10.1 (audit trails for network activity)
    Checks whether VPC flow logs are enabled for VPCs in the account.
    """
    ec2 = boto3.client('ec2')
    results = []

    vpcs = ec2.describe_vpcs()['Vpcs']
    flow_logs = ec2.describe_flow_logs()['FlowLogs']

    # Build a set of VPC IDs that already have an active flow log
    vpcs_with_logs = {
        fl['ResourceId'] for fl in flow_logs
        if fl.get('FlowLogStatus') == 'ACTIVE'
    }

    if not vpcs:
        results.append({
            'resource': 'N/A',
            'status': 'PASS',
            'detail': 'No VPCs found in this account/region',
            'pci_requirement': '10.1'
        })
        return results

    for vpc in vpcs:
        vpc_id = vpc['VpcId']

        if vpc_id in vpcs_with_logs:
            results.append({
                'resource': vpc_id,
                'status': 'PASS',
                'detail': 'VPC flow logs are enabled',
                'pci_requirement': '10.1'
            })
        else:
            results.append({
                'resource': vpc_id,
                'status': 'FAIL',
                'detail': 'VPC flow logs are not enabled',
                'pci_requirement': '10.1'
            })

    return results


def check_password_policy():
    """
    PCI-DSS Requirement 8.2 (strong password requirements)
    Checks whether an IAM account password policy is configured
    with minimum length and complexity requirements.
    """
    iam = boto3.client('iam')
    results = []

    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
    except iam.exceptions.NoSuchEntityException:
        results.append({
            'resource': 'Account Password Policy',
            'status': 'FAIL',
            'detail': 'No password policy configured for this account',
            'pci_requirement': '8.2'
        })
        return results

    min_length = policy.get('MinimumPasswordLength', 0)
    requires_symbols = policy.get('RequireSymbols', False)
    requires_numbers = policy.get('RequireNumbers', False)
    requires_uppercase = policy.get('RequireUppercaseCharacters', False)
    requires_lowercase = policy.get('RequireLowercaseCharacters', False)

    meets_requirements = (
        min_length >= 8 and
        requires_symbols and
        requires_numbers and
        requires_uppercase and
        requires_lowercase
    )

    if meets_requirements:
        results.append({
            'resource': 'Account Password Policy',
            'status': 'PASS',
            'detail': f'Password policy meets minimum requirements (length: {min_length})',
            'pci_requirement': '8.2'
        })
    else:
        results.append({
            'resource': 'Account Password Policy',
            'status': 'FAIL',
            'detail': f'Password policy does not meet minimum requirements (length: {min_length})',
            'pci_requirement': '8.2'
        })

    return results

if __name__ == "__main__":
    print("=== S3 Public Access Check ===")
    for r in check_s3_public_access():
        print(r)

    print("\n=== S3 Encryption Check ===")
    for r in check_s3_encryption():
        print(r)

    print("\n=== EBS Encryption Check ===")
    for r in check_ebs_encryption():
        print(r)

    print("\n=== Security Groups Check ===")
    for r in check_security_groups():
        print(r)

    print("\n=== IAM MFA Check ===")
    for r in check_iam_mfa():
        print(r)

    print("\n=== IAM Access Key Age Check ===")
    for r in check_iam_key_age():
        print(r)

    print("\n=== RDS Security Check ===")
    for r in check_rds_security():  
        print(r)

    print("\n=== CloudTrail Check ===")
    for r in check_cloudtrail():
        print(r)

    print("\n=== VPC Flow Logs Check ===")
    for r in check_vpc_flow_logs(): 
        print(r)

    print("\n=== Password Policy Check ===")
    for r in check_password_policy():
        print(r)