import boto3
from checks import (
    check_s3_public_access,
    check_s3_encryption,
    check_ebs_encryption,
    check_security_groups,
    check_iam_mfa,
    check_iam_key_age,
    check_rds_security,
    check_cloudtrail,
    check_vpc_flow_logs,
    check_password_policy,
)
from report import generate_html_report

REPORT_BUCKET = "pcidss-reports-sp-2026"

def lambda_handler(event, context):
    checks = [
        check_s3_public_access,
        check_s3_encryption,
        check_ebs_encryption,
        check_security_groups,
        check_iam_mfa,
        check_iam_key_age,
        check_rds_security,
        check_cloudtrail,
        check_vpc_flow_logs,
        check_password_policy,
    ]

    all_results = []
    for check_func in checks:
        all_results.extend(check_func())

    # Lambda's only writable directory is /tmp
    local_path = "/tmp/compliance_report.html"
    generate_html_report(all_results, output_file=local_path)

    s3 = boto3.client('s3')
    s3.upload_file(local_path, REPORT_BUCKET, "compliance_report.html")

    total = len(all_results)
    passed = sum(1 for r in all_results if r['status'] == 'PASS')
    compliance_pct = round((passed / total) * 100) if total > 0 else 0

    return {
        "statusCode": 200,
        "body": f"Scan complete. Compliance score: {compliance_pct}%. Report uploaded to s3://{REPORT_BUCKET}/compliance_report.html"
    }