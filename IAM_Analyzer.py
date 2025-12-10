import boto3
import json

iam = boto3.client('iam')

def check_policy_for_god_mode(policy_arn):
    """
    Looks at the default version of an IAM policy and checks
    if it contains 'Allow * on *' (full admin access).
    """
    findings = []

    try:
        # Get default version
        policy_meta = iam.get_policy(PolicyArn=policy_arn)['Policy']
        version_id = policy_meta['DefaultVersionId']

        # Fetch policy document
        version_info = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        doc = version_info['PolicyVersion']['Document']

        # Loop through all statements
        for stmt in doc.get('Statement', []):
            effect = stmt.get('Effect')
            action = stmt.get('Action')
            resource = stmt.get('Resource')

            # Normalize to list
            if isinstance(action, str):
                action = [action]
            if isinstance(resource, str):
                resource = [resource]

            # Look for full “Allow everything”
            if (
                effect == "Allow" and
                "*" in action and
                "*" in resource
            ):
                findings.append(
                    f"God-mode access found in statement {stmt.get('Sid', 'N/A')} "
                    f"(Allow * on *)."
                )

    except iam.exceptions.NoSuchEntityException:
        findings.append(f"Policy not found: {policy_arn}")
    except Exception as e:
        findings.append(f"Error checking policy {policy_arn}: {e}")

    return findings


def audit_all_iam_policies():
    """Checks all customer-managed IAM policies for overly permissive rules."""
    print("\n--- IAM Policy Analyzer ---")

    try:
        # Local scope → customer-managed policies only
        policies = iam.list_policies(Scope='Local')['Policies']
    except Exception as e:
        print(f"Failed to list policies. Check permissions. Error: {e}")
        return

    found_risky = False

    for policy in policies:
        arn = policy['Arn']
        name = policy['PolicyName']

        results = check_policy_for_god_mode(arn)
        if results:
            found_risky = True
            print(f"\nPotentially risky policy: {name}")
            for r in results:
                print(f" - {r}")

    if not found_risky:
        print("\nNo policies with full wildcard access detected.")

if __name__ == "__main__":
    audit_all_iam_policies()
