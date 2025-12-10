import boto3
import argparse
import sys

# Initialize EC2 client
try:
    ec2 = boto3.client("ec2")
except Exception as e:
    print(f"FATAL: Unable to initialize EC2 client. Check AWS config. ({e})")
    sys.exit(1)


# ------------------ Helpers ------------------

def protocol_to_num(proto):
    """Map protocol names to the numbers used in NACLs."""
    mapping = {
        "icmp": "1",
        "tcp": "6",
        "udp": "17",
        "all": "-1",
        "any": "-1"
    }
    return mapping.get(proto.lower(), proto)


# ------------------ Core Checks ------------------

def get_instance_details(instance_id):
    """Get instance metadata: state, SGs, subnet, VPC, public/private state."""
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        inst = resp["Reservations"][0]["Instances"][0]

        state = inst["State"]["Name"]
        if state != "running":
            return {"error": f"Instance is '{state}', not running. Connectivity won't work."}

        sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
        subnet = inst.get("SubnetId")
        vpc = inst.get("VpcId")

        # Check if it has a public IP or EIP association
        is_public = (
            "PublicIpAddress" in inst
            or inst.get("NetworkInterfaces", [{}])[0]
                  .get("Association", {})
                  .get("PublicIp")
        )

        return {
            "state": state,
            "sg_ids": sg_ids,
            "subnet": subnet,
            "vpc": vpc,
            "is_public": bool(is_public)
        }

    except ec2.exceptions.InvalidInstanceID.NotFound:
        return {"error": f"Instance ID '{instance_id}' not found."}
    except Exception as e:
        return {"error": f"Failed pulling instance details: {e}"}


def check_sg_rules(sg_ids, protocol, port):
    """
    Basic SG check:
    Confirm if anything allows inbound protocol/port from 0.0.0.0/0.
    """
    source = "0.0.0.0/0"

    for sg in sg_ids:
        info = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]

        for rule in info.get("IpPermissions", []):
            proto_match = (rule.get("IpProtocol") == "-1" or rule.get("IpProtocol") == protocol)

            port_match = False
            if rule.get("FromPort") is not None and rule.get("ToPort") is not None:
                if rule["FromPort"] <= port <= rule["ToPort"]:
                    port_match = True

            src_match = any(
                ip.get("CidrIp") == source for ip in rule.get("IpRanges", [])
            )

            if proto_match and port_match and src_match:
                return f"SG {sg} allows inbound {protocol}/{port} from anywhere ({source})."

    return f"No SG rule found allowing inbound {protocol}/{port} from {source}."


def check_nacl(subnet_id, protocol, port):
    """Check matching NACL inbound + outbound rules."""
    resp = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )

    if not resp["NetworkAcls"]:
        return "No NACL found for this subnet."

    nacl = resp["NetworkAcls"][0]
    proto_num = protocol_to_num(protocol)

    report = [f"NACL: {nacl['NetworkAclId']}"]

    def eval_rules(entries, is_egress):
        label = "Egress" if is_egress else "Ingress"

        for rule in sorted(entries, key=lambda r: r["RuleNumber"]):
            if rule["Egress"] != is_egress:
                continue
            if rule["RuleNumber"] == 32767:
                continue  # default deny handled later

            protocol_ok = (
                rule.get("Protocol") == "-1"
                or str(rule.get("Protocol")) == proto_num
            )

            port_ok = False
            if "PortRange" in rule:
                p1 = rule["PortRange"]["From"]
                p2 = rule["PortRange"]["To"]
                if p1 <= port <= p2:
                    port_ok = True
            elif rule.get("Protocol") == "-1":
                port_ok = True

            if protocol_ok and port_ok:
                if rule["RuleAction"] == "allow":
                    report.append(f"{label}: Rule {rule['RuleNumber']} ALLOWS traffic.")
                    return True
                else:
                    report.append(f"{label}: Rule {rule['RuleNumber']} DENIES traffic.")
                    return False

        report.append(f"{label}: No matching ALLOW, default deny applies.")
        return False

    report.append("\nIngress:")
    eval_rules(nacl["Entries"], is_egress=False)

    report.append("\nEgress:")
    eval_rules(nacl["Entries"], is_egress=True)

    return "\n".join(report)


def check_routes(subnet_id, is_public):
    """Look for a 0.0.0.0/0 route and verify it points to the correct gateway."""
    resp = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )

    if not resp["RouteTables"]:
        return "No route table found for this subnet."

    rt = resp["RouteTables"][0]
    report = [f"Route Table: {rt['RouteTableId']}"]

    for r in rt["Routes"]:
        if r.get("DestinationCidrBlock") != "0.0.0.0/0":
            continue

        target = (
            r.get("GatewayId")
            or r.get("NatGatewayId")
            or r.get("NetworkInterfaceId")
        )

        if is_public:
            if target and str(target).startswith("igw-"):
                report.append(f"Default route → {target} (IGW). OK for public instance.")
            else:
                report.append(f"Default route target looks wrong ({target}). Public instances need an IGW.")
        else:
            if target and ("nat-" in target or "eni-" in target):
                report.append(f"Default route → {target}. OK for private outbound access.")
            else:
                report.append(f"Private instance route doesn't point to a NAT/ENI ({target}).")

        return "\n".join(report)

    report.append("No default 0.0.0.0/0 route found.")
    return "\n".join(report)


# ------------------ Main ------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EC2 connectivity troubleshooting helper")
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()

    print(f"\nEC2 Connectivity Check: {args.instance_id} ({args.protocol}/{args.port})")
    print("------------------------------------------------------------")

    details = get_instance_details(args.instance_id)
    if "error" in details:
        print(details["error"])
        sys.exit(1)

    print(
        f"Instance State: {details['state']} | "
        f"Public: {details['is_public']} | "
        f"Subnet: {details['subnet']}"
    )
    print("------------------------------------------------------------\n")

    # 1. SG check
    print("1. Security Groups")
    print(check_sg_rules(details["sg_ids"], args.protocol, args.port))
    print("\n------------------------------------------------------------\n")

    # 2. NACL check
    print("2. Network ACL")
    print(check_nacl(details["subnet"], args.protocol, args.port))
    print("\n------------------------------------------------------------\n")

    # 3. Route table
    print("3. Route Table")
    print(check_routes(details["subnet"], details["is_public"]))
    print("\nDone.\n")
