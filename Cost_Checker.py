# Cost_Checker.py — basic EC2/S3/etc cost cleanup helper

import boto3
import sys
import io

# ---- Windows console UTF-8 fix ----
# (Windows hates unicode output... this avoids those weird encoding crashes.)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Some rough cost reference values.
# These are not exact AWS numbers — just ballpark figures to give an idea.
ESTIMATED_RATES = {
    "eip_unattached": 3.65,
    "ebs_standard_gb": 0.06,
    "ec2_stopped_t2_micro": 1.00
}

# Try initializing EC2 client
try:
    ec2_client = boto3.client("ec2")
except Exception as e:
    print(f"[FATAL] Couldn't init EC2 client. Check AWS creds/config. Error: {e}")
    sys.exit(1)


# -----------------------
# Audit Functions
# -----------------------

def audit_unattached_eips():
    """Return a list of unattached EIPs."""
    results = []
    try:
        data = ec2_client.describe_addresses()
        for addr in data.get("Addresses", []):
            if "AssociationId" not in addr:
                results.append({
                    "PublicIp": addr.get("PublicIp"),
                    "AllocationId": addr.get("AllocationId")
                })
    except Exception as e:
        print(f"[!] Error while checking EIPs: {e}")
    return results


def audit_unused_ebs_volumes():
    """Return all EBS volumes in 'available' state."""
    vols = []
    try:
        data = ec2_client.describe_volumes(
            Filters=[{"Name": "status", "Values": ["available"]}]
        )
        for volume in data.get("Volumes", []):
            if not volume.get("Attachments"):
                vols.append({
                    "VolumeId": volume.get("VolumeId"),
                    "SizeGB": volume.get("Size"),
                    "VolumeType": volume.get("VolumeType"),
                    "CreateTime": volume.get("CreateTime").strftime("%Y-%m-%d")
                })
    except Exception as e:
        print(f"[!] Error while checking EBS volumes: {e}")
    return vols


def audit_stopped_ec2_instances():
    """Return instances that are currently stopped."""
    items = []
    try:
        data = ec2_client.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        )
        for res in data.get("Reservations", []):
            for inst in res.get("Instances", []):
                items.append({
                    "InstanceId": inst.get("InstanceId"),
                    "InstanceType": inst.get("InstanceType"),
                    "LaunchTime": inst["LaunchTime"].strftime("%Y-%m-%d") if inst.get("LaunchTime") else "N/A"
                })
    except Exception as e:
        print(f"[!] Error while checking stopped instances: {e}")
    return items


# -----------------------
# Cost Calculation + Report
# -----------------------

def generate_cost_report(eips, volumes, instances):
    out = []
    total = 0.0

    # 1. EIPs
    out.append("\n## 1. Unattached Elastic IPs")
    if eips:
        est = len(eips) * ESTIMATED_RATES["eip_unattached"]
        total += est
        out.append(f"⚠ Found {len(eips)} unattached EIP(s).")
        out.append(f"   Est. Monthly Savings: ${est:.2f}")
        for e in eips:
            out.append(f"   - {e['PublicIp']} (Alloc: {e['AllocationId']})")
    else:
        out.append("✓ No unattached EIPs.")

    out.append("\n" + "-" * 55)

    # 2. EBS volumes
    out.append("\n## 2. Unused EBS Volumes")
    if volumes:
        total_size = sum(v["SizeGB"] for v in volumes)
        est = total_size * ESTIMATED_RATES["ebs_standard_gb"]
        total += est

        out.append(f"⚠ Found {len(volumes)} unused volume(s). Total: {total_size} GB")
        out.append(f"   Est. Monthly Savings: ${est:.2f}")
        for v in volumes:
            out.append(
                f"   - {v['VolumeId']} | {v['SizeGB']}GB | {v['VolumeType']} | Created {v['CreateTime']}"
            )
    else:
        out.append("✓ No unused EBS volumes.")

    out.append("\n" + "-" * 55)

    # 3. Stopped EC2 instances
    out.append("\n## 3. Stopped EC2 Instances")
    if instances:
        est = len(instances) * ESTIMATED_RATES["ec2_stopped_t2_micro"]
        total += est
        out.append(f"⚠ {len(instances)} instance(s) are stopped.")
        for i in instances:
            out.append(
                f"   - {i['InstanceId']} | {i['InstanceType']} | Launched {i['LaunchTime']}"
            )
    else:
        out.append("✓ No stopped instances.")

    out.append("\n=======================================================")
    out.append(f" Total Estimated Monthly Savings: ${total:.2f}")
    out.append("=======================================================")

    return "\n".join(out)


# -----------------------
# Main
# -----------------------

if __name__ == "__main__":
    print("\n--- Cost Optimization Checker ---")

    eips = audit_unattached_eips()
    volumes = audit_unused_ebs_volumes()
    instances = audit_stopped_ec2_instances()

    report = generate_cost_report(eips, volumes, instances)
    print(report)
