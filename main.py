from report import generate_html_report
from checks import(
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

def run_all_checks():
    all_results = []


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

    for check_func in checks:
        results = check_func()
        all_results.extend(results)

    return all_results

def print_summary(results):
    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'PASS')
    failed = sum(1 for r in results if r['status'] == 'FAIL')
    compliance_percentage = round((passed / total) * 100) if total > 0 else 0


    print("\n" + "=" *50)
    print("PCI-DSS COMPLIANCE SUMMARY")
    print("=" * 50)
    print(f"Total Checks: {total}")
    print(f"Passed Checks: {passed}")
    print(f"Failed Checks: {failed}")
    print(f"Compliance Score: {compliance_percentage}%")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    results = run_all_checks()

    print("=== Full PCI-DSS Compliance Report ===")
    for r in results:
        print(r)


    print_summary(results)
    generate_html_report(results)