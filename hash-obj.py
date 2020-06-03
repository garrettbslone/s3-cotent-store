import argparse
import sys

from boto3.session import Session
from botocore.exceptions import *
from hashlib import sha1, sha256


def get_args():
    parser = argparse.ArgumentParser(description="Process args for loading or storing data to s3 object store")

    parser.add_argument("action", metavar="load\n  store", choices=["load", "store"])

    parser.add_argument("-a", "--access_key", type=str, required=True)
    parser.add_argument(
        "-b", "--bucket-name", required=False, default="flux-minio", type=str
    )
    parser.add_argument("-e", "--endpoint", type=str, required=True)
    parser.add_argument(
        "-H",
        "--hash-function",
        choices=["sha1", "sha256"],
        type=str,
        required=False,
        default="sha1",
    )
    parser.add_argument("-s", "--secret_key", type=str, required=True)

    return parser.parse_args()


def hash_blob(blob, hash_func):
    blobref = None
    hash_func = str(hash_func)

    if "256" in hash_func:
        blobref = "sha256-" + sha256(blob).hexdigest()

    elif "1" in hash_func:
        blobref = "sha1-" + sha1(blob).hexdigest()

    return blobref


def get_s3_connection(endpoint, access_key, secret_key):
    connection = None

    try:
        session = Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        connection = session.resource(service_name="s3", endpoint_url=endpoint).meta.client

    except (ProfileNotFound, EndpointConnectionError) as e:
        print(e, type(e))

    return connection


def bucket_exists(connection, bucket_name):
    exists = True

    try:
        connection.head_bucket(Bucket=bucket_name)

    except ClientError:
        exists = False

    return exists


def store_object(connection, bucket_name, blob, hash_func):
    blobref = hash_blob(blob, hash_func)

    try:
        connection.put_object(Bucket=bucket_name, Key=blobref, Body=blob)

    except ClientError as e:
        print(e, type(e))

    return blobref


def load_object(connection, bucket_name, blobref):
    blob = None

    try:
        blob = connection.get_object(Bucket=bucket_name, Key=blobref)["Body"].read()

    except ClientError as e:
        print(e, type(e))

    return blob


def main():
    args = get_args()

    conn = get_s3_connection(args.endpoint, args.access_key, args.secret_key)

    if not bucket_exists(conn, args.bucket_name):
        conn.create_bucket(Bucket=args.bucket_name)

    if args.action == "store":
        blob = sys.stdin.buffer.read()
        
        blobref = store_object(conn, args.bucket_name, blob, args.hash_function)
        print(blobref)

    else:
        blobref = sys.stdin.read()[:-1]
        
        blob = load_object(conn, args.bucket_name, blobref)
        print(blob)


if __name__ == "__main__":
    main()
