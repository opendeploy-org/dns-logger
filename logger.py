import os
import io
import re
import json
import time
import zipfile
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta

import jwt
import boto3
import requests
import tldextract

LOG_EVENTS = ["DisableDomainTransferLock",
              "UpdateDomainNameservers", "ChangeResourceRecordSets"]
TRUSTED_COMMIT_SHA = []
AWS_NS_REGEX = re.compile(r"^ns-\d+\.awsdns-\d+\.(com|net|org|co\.uk)$")


def get_account_id(boto3_session):
    try:
        client = boto3_session.client("sts")
        response = client.get_caller_identity()

        return response["Account"]
    except Exception as e:
        raise Exception(f"Failed to get AWS account ID: {e}")


def gen_wildcard_candidates(subdomain):
    labels = subdomain.strip('.').split('.')
    candidates = []

    for i in range(1, len(labels) - 1):
        domain = ".".join(labels[i:])
        candidates.append(f"*.{domain}")

    return candidates


def check_dns_init_state(boto3_session, subdomain):
    try:
        # parse subdomain
        ext_result = tldextract.extract(subdomain)
        root_domain = ext_result.top_domain_under_public_suffix
        sub_domain = ext_result.fqdn

        # check route53 register state
        register_client = boto3_session.client(
            "route53domains", region_name="us-east-1")
        list_domains_paginator = register_client.get_paginator("list_domains")
        domain_founded = False

        # find registered domain by root domain
        for page in list_domains_paginator.paginate():
            for domain in page["Domains"]:
                if domain["DomainName"] == root_domain:
                    # check transfer lock state
                    if not domain["TransferLock"]:
                        raise Exception("Transfer lock is disabled")

                    # check domain nameservers
                    domain_detail_res = register_client.get_domain_detail(
                        DomainName=root_domain)

                    for nameserver in domain_detail_res["Nameservers"]:
                        if not AWS_NS_REGEX.match(nameserver["Name"]):
                            raise Exception(f"The domain is using a non-AWS nameserver ({nameserver["Name"]})")

                    domain_founded = True
                    break

        if not domain_founded:
            raise Exception("Unable to find domain")

        # check DNS record state
        route53_client = boto3_session.client("route53")
        hosted_zones_paginator = route53_client.get_paginator(
            "list_hosted_zones")

        # find hosted zones by root domain
        for page in hosted_zones_paginator.paginate():
            for hosted_zone in page["HostedZones"]:
                if hosted_zone["Name"].rstrip(".") == root_domain.rstrip("."):
                    hosted_zone_id = hosted_zone["Id"].split("/")[-1]
                    candidates = gen_wildcard_candidates(sub_domain)

                    # check that the subdomain does not have any A/AAAA/MX/CNAME/SRV DNS records
                    record_sets_res = route53_client.list_resource_record_sets(
                        HostedZoneId=hosted_zone_id,
                    )

                    for record_set in record_sets_res["ResourceRecordSets"]:
                        normalized_record_name = record_set["Name"].rstrip(
                            ".").replace("\052", "*")
                        if normalized_record_name == sub_domain.rstrip(".") and normalized_record_name in candidates:
                            if record_set["Type"] in ["A", "AAAA", "MX", "CNAME", "SRV"]:
                                raise Exception(f"Invalid initial state of DNS record {record_set["Name"]} with type {record_set["Type"]}")

                    return hosted_zone_id
    except Exception as e:
        raise Exception(f"Failed to check DNS initial state: {e}")


def load_log_from_url(log_dwonload_url):
    try:
        response = requests.get(log_dwonload_url)
        response.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            required_files = {"log.json", "attestation.json"}
            found_files = set(zip_file.namelist())

            if not required_files.issubset(found_files):
                missing = required_files - found_files
                raise Exception(
                    f"Missing file(s) in downloaded log: {', '.join(missing)}")

            log_data_bytes = zip_file.read("log.json")
            log_attestation_bytes = zip_file.read("attestation.json")

            return log_data_bytes, log_attestation_bytes
    except Exception as e:
        raise Exception(f"Failed to download log: {e}")


def extract_workflow_envs(id_token):
    payload = jwt.decode(id_token, options={"verify_signature": False})

    return payload["repository_owner"], payload["job_workflow_sha"]


def verify_past_log(id_token, log_data_bytes, log_attestation_bytes):
    try:
        owner, curr_commit_sha = extract_workflow_envs(id_token)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # save the log data and attestation to temp folder
            log_path = Path(tmp_dir) / "log.json"
            attestation_path = Path(tmp_dir) / "attestation.json"

            with open(log_path, "wb") as f:
                f.write(log_data_bytes)

            with open(attestation_path, "wb") as f:
                f.write(log_attestation_bytes)

            # execute gh attestation verify
            cmd = [
                "gh", "attestation", "verify",
                "--owner", owner,
                "-b", attestation_path,
                log_path,
                "--signer-workflow", "opendeploy-org/ods-dns-logger/.github/workflows/ods-dns-logger.yml",
                "--format", "json"
            ]
            cmd_output = subprocess.run(
                cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

            attest_result = json.loads(cmd_output)[0]
            signer_commit_sha = attest_result["verificationResult"]["signature"]["certificate"]["buildSignerDigest"]

            # check the signer commmit sha of attestation
            if signer_commit_sha != curr_commit_sha and signer_commit_sha not in TRUSTED_COMMIT_SHA:
                raise Exception("Unknown signer commit sha")
    except Exception as e:
        raise Exception(f"Failed to validate past log: {e}")


def lookup_event_records(boto3_session, event_name, start_time):
    try:
        client = boto3_session.client("cloudtrail", region_name="us-east-1")
        paginator = client.get_paginator("lookup_events")

        events = []
        page_iterator = paginator.paginate(
            LookupAttributes=[{
                "AttributeKey": "EventName",
                "AttributeValue": event_name
            }],
            StartTime=start_time
        )

        for page in page_iterator:
            for event in page["Events"]:
                event_detail = json.loads(event["CloudTrailEvent"])
                events.append(event_detail)

        return events
    except Exception as e:
        raise Exception(f"Failed to lookup event records: {e}")


def merge_event_records(past_events, new_events):
    unique = {event["eventID"]: event for event in past_events + new_events}

    return sorted(
        unique.values(),
        key=lambda x: datetime.fromisoformat(
            x["eventTime"].replace("Z", "+00:00"))
    )


def main():
    # retrieve parameters
    params = {
        "subdomain": os.environ.get("SUBDOMAIN"),
        "logDownloadURL": os.environ.get("LOG_DOWNLOAD_URL"),
        "awsAccessKey": os.environ.get("AWS_ACCESS_KEY"),
        "awsAccessSecret": os.environ.get("AWS_ACCESS_SECRET"),
        "idToken": os.environ.get("ID_TOKEN"),
        "outputFolder": os.environ.get("OUTPUT_FOLDER")
    }

    is_success = False
    boto3_session = boto3.Session(
        aws_access_key_id=params["awsAccessKey"],
        aws_secret_access_key=params["awsAccessSecret"],
    )

    try:
        log_data = None
        curr_time = int(time.time())
        account_id = get_account_id(boto3_session)

        if not params["logDownloadURL"]:
            # first time to create a log
            print("Checking DNS initial state")
            hosted_zone_id = check_dns_init_state(
                boto3_session, params["subdomain"])

            # create the log data
            log_data = {
                "subdomain": params["subdomain"],
                "accountID": account_id,
                "hostedZoneID": hosted_zone_id,
                "firstLogTime": curr_time,
                "lastLogTime": curr_time,
                "logs": {}
            }

            for log_event in LOG_EVENTS:
                log_data["logs"][log_event] = []
        else:
            # download and verify past log data
            print("Loading past log data")
            past_log_data_btyes, past_log_attestation_btyes = load_log_from_url(
                params["logDownloadURL"])
            past_log_data = json.loads(past_log_data_btyes
                                       )
            print("Verifying past log data")
            verify_past_log(params["idToken"],
                            past_log_data_btyes, past_log_attestation_btyes)

            if past_log_data["subdomain"] != past_log_data["subdomain"]:
                raise Exception(f"The subdomain differs from past log data")

            if account_id != past_log_data["accountID"]:
                raise Exception(f"The account ID differs from past log data")

            if curr_time - past_log_data["lastLogTime"] > 30 * 24 * 60 * 60:
                raise Exception(f"The past log data is more than 30 days old")

            # create the log data
            log_data = {
                "subdomain": past_log_data["subdomain"],
                "accountID": past_log_data["accountID"],
                "hostedZoneID": past_log_data["hostedZoneID"],
                "firstLogTime": past_log_data["firstLogTime"],
                "lastLogTime": curr_time,
                "logs": {}
            }

            # lookup DNS events
            lookup_start_time = datetime.fromtimestamp(
                past_log_data["lastLogTime"], tz=timezone.utc) - timedelta(hours=6)
            for event_name in LOG_EVENTS:
                if event_name not in past_log_data["logs"]:
                    raise Exception(f"Event type is missing from past log")

                print(f"Looking up {event_name} evetns")
                event_data = lookup_event_records(
                    boto3_session, event_name, lookup_start_time)

                log_data["logs"][event_name] = merge_event_records(
                    past_log_data["logs"][event_name], event_data)

        # save log data to output folder
        with open(Path(params["outputFolder"]) / "log.json", "w") as json_file:
            json.dump(log_data, json_file)

        is_success = True
    except Exception as e:
        print(e)

    if not is_success:
        exit(1)


if __name__ == "__main__":
    main()
