import boto3
import json

s3 = boto3.client('s3')

def check_bucket_exposure(bucket_name):
    """
    Basic checks to identify if an S3 bucket is publicly accessible through:
      - Public Access Block settings
      - ACL permissions
      - Bucket policy
    """
    findings = []

    # --- Public Access Block Check ---
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']

        # If any of these are False, the bucket might be exposed
        pab_risky = (
            not pab.get('BlockPublicAcls', True) or
            not pab.get('IgnorePublicAcls', True) or
            not pab.get('BlockPublicPolicy', True) or
            not pab.get('RestrictPublicBuckets', True)
        )

        if pab_risky:
            findings.append("Public Access Block is not fully enabled — bucket may be exposed.")
        else:
            findings.append("Public Access Block looks good.")
    except Exception:
        findings.append("Public Access Block config missing or not accessible.")

    # --- ACL Check ---
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission')

            public_group = grantee.get('URI')

            if public_group in [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            ]:
                findings.append(f"ACL exposes bucket: {public_group.split('/')[-1]} has {permission}.")
    except Exception as e:
        findings.append(f"Could not read ACL (may be policy-only bucket). Error: {e}")

    # --- Policy Check ---
    try:
        policy_raw = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
        policy = json.loads(policy_raw)

        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') != "Allow":
                continue

            principal = stmt.get('Principal')
            actions = stmt.get('Action')

            # handle both list and string forms
            if isinstance(actions, str):
                actions = [actions]

            is_public_principal = (
                principal == "*" or
                (isinstance(principal, dict) and principal.get("AWS") == "*")
            )

            risky_actions = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject']

            if is_public_principal and any(a in actions for a in risky_actions):
                findings.append(
                    f"Bucket policy may expose data: Statement {stmt.get('Sid', 'N/A')} "
                    f"allows {actions} for public principal '*'."
                )
    except s3.exceptions.NoSuchBucketPolicy:
        findings.append("No bucket policy found.")
    except Exception as e:
        findings.append(f"Error checking bucket policy: {e}")

    return findings


def audit_all_s3_buckets():
    """Lists all buckets and runs the exposure checks."""
    print("\n--- S3 Bucket Auditor ---")

    try:
        buckets = [b['Name'] for b in s3.list_buckets().get('Buckets', [])]
    except Exception as e:
        print(f"Failed to list buckets. Check IAM permissions. Error: {e}")
        return

    if not buckets:
        print("No buckets found.")
        return

    for bucket in buckets:
        print(f"\nChecking bucket: {bucket}")
        results = check_bucket_exposure(bucket)

        if not results:
            print("  No major issues detected.")
            continue

        for r in results:
            print(f"  - {r}")


if __name__ == "__main__":
    audit_all_s3_buckets()
