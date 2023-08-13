"""Adds SSL bucket policy to S3 buckets if not already exist."""

import json
import os
import concurrent.futures
import boto3

from botocore.exceptions import ClientError

AWS_BUCKETS = os.environ.get("AWS_BUCKETS", None)

session = boto3.Session(
    profile_name=os.environ.get("AWS_PROFILE"),
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.environ.get("AWS_SESSION_TOKEN"))
s3 = session.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1"))

def prepare_policy(bucket, existing_policy=None):
    """Checks if SSL statement already exist in the bucket policy and
    returns the updated policy if not exist."""

    ssl_deny_policy_statement = {
        "Sid": "AllowSSLRequestsOnly",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{bucket}",
            f"arn:aws:s3:::{bucket}/*"
        ],
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    }

    if existing_policy is None:
        return {
            "Version": "2012-10-17",
            "Statement": [ssl_deny_policy_statement]
        }
    else:
        policy_statements = json.loads(existing_policy)["Statement"]
        print(f"[{bucket}] Checking if SSL statement already exists...")
        contains_ssl_statement = False
        for statement in policy_statements:
            if (
                ("Condition" in statement and "Bool" in statement["Condition"]
                and "aws:SecureTransport" in statement["Condition"]["Bool"]
                and statement["Condition"]["Bool"]["aws:SecureTransport"].lower() == "false")
                and statement["Effect"].lower() == "deny" and statement["Action"].lower() == "s3:*"
                and statement["Principal"] == "*"
            ):
                contains_ssl_statement = True
                break

        if contains_ssl_statement:
            print(f"[{bucket}] SSL statement already exist")
            return None

        policy_statements.append(ssl_deny_policy_statement)

        return {
            "Version": "2012-10-17",
            "Statement": policy_statements
        }

def add_policy(bucket):
    """Adds SSL bucket policy to the bucket if not already exist."""

    try:
        print(f"[{bucket}] Fetching existing bucket policy...")
        response = s3.get_bucket_policy(
            Bucket=bucket
        )
        print(f"[{bucket}] Existing bucket policy found")
        existing_policy = response["Policy"]
    except ClientError as client_error:
        if client_error.response["Error"]["Code"] == "NoSuchBucketPolicy":
            print(f"[{bucket}] No existing bucket policy found")
            existing_policy = None
        else:
            raise client_error

    print(f"[{bucket}] Preparing bucket policy...")
    bucket_policy = prepare_policy(bucket, existing_policy)

    if bucket_policy is not None:
        try:
            print(f"[{bucket}] {'Attaching' if not existing_policy else 'Updating'} bucket policy...")
            s3.put_bucket_policy(
                Bucket=bucket,
                Policy=json.dumps(bucket_policy)
            )
            print(f"[{bucket}] Policy successfully {'attached' if not existing_policy else 'updated'}")
            return {
                "status": "ok",
                "bucket": bucket
            }
        except ClientError as client_error:
            print(f"[{bucket}] Failed to attach policy. Reason: {client_error}")
            return {
                "status": "fail",
                "bucket": bucket
            }
    else:
        print(f"[{bucket}] Skipping updating policy because SSL statement already exist")
        return {
            "status": "skip",
            "bucket": bucket
        }

def update_bucket_policy(buckets):
    """Update bucket policy for the given bucket(s)."""

    with concurrent.futures.ThreadPoolExecutor(10) as executor:
        results = [executor.submit(add_policy, bucket) for bucket in buckets]

    applied_buckets = []
    failed_buckets = []
    skipped_buckets = []
    try:
        for future in results:
            if future.result()["status"] == "ok":
                applied_buckets.append(future.result()["bucket"])
            elif future.result()["status"] == "fail":
                failed_buckets.append(future.result()["bucket"])
            elif future.result()["status"] == "skip":
                skipped_buckets.append(future.result()["bucket"])
    except Exception as exception:
        print(f"Error: {exception}")

    print(f"\nTotal bucket count: {len(applied_buckets) + len(failed_buckets) + len(skipped_buckets)}")

    print("==========================")
    print(f"SSL statement applied to {len(applied_buckets)} bucket(s)")
    if len(applied_buckets) > 0:
        print("> {}".format("\n> ".join(applied_buckets)))
    print("==========================")

    print("==========================")
    print(f"SSL statement failed for {len(failed_buckets)} bucket(s)")
    if len(failed_buckets) > 0:
        print("> {}".format("\n> ".join(failed_buckets)))
    print("==========================")

    print("==========================")
    print(f"SSL statement skipped for {len(skipped_buckets)} bucket(s)")
    if len(skipped_buckets) > 0:
        print("> {}".format("\n> ".join(skipped_buckets)))
    print("==========================")

if AWS_BUCKETS is None:
    print("""Error: AWS_BUCKETS cannot be blank.

To add SSL policy to the bucket(s) the value for AWS_BUCKETS variable needs to be either of the following:
- Single bucket: abc
- Multiple buckets: bucket1, bucket2, bucket10
- All buckets: all

For AWS authentication please use the following variables:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_SESSION_TOKEN
- AWS_REGION
- AWS_PROFILE""")
    print("""
Usage: AWS_BUCKETS=all python3 s3_ssl_bucket_policy.py
""")
else:
    print("Preparing bucket(s)...", end=" ", flush=True)
    if AWS_BUCKETS.lower() == "all":
        resp = s3.list_buckets()
        AWS_BUCKET_NAMES = [b["Name"] for b in resp["Buckets"]]
    elif "," in AWS_BUCKETS:
        AWS_BUCKET_NAMES = [r.strip() for r in AWS_BUCKETS.split(",")]
    else:
        AWS_BUCKET_NAMES = [AWS_BUCKETS]
    print("ok")

    ARRAY_JOINER = "\n> "
    print("==============================================")
    print(f"SSL statement will be added to the following bucket(s) \
if not already present: \n> {ARRAY_JOINER.join(AWS_BUCKET_NAMES)}")
    print("==============================================")
    resp = input("Are you sure you want to continue (Y/n): ").lower()
    if resp in {"y", ""}:
        update_bucket_policy(AWS_BUCKET_NAMES)
    else:
        print("Exiting as per user input")
