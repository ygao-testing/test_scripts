import logging
import collections
import time
import botocore
from fortiqa.libs.aws.data_class.s3_data_classes import S3Bucket
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.tests import settings
from fortiqa.libs.helper.date_helper import datetime_to_iso8601
from operator import itemgetter

logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


class S3Helper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client="s3", region=region, aws_credentials=aws_credentials)

    def get_all_s3_buckets_raw(self, tags: dict[str, str] | None = None) -> list[dict]:
        """Retrieve a raw list of all S3 buckets in the AWS account, optionally filtering by tags.

        If tags are provided, this method fetches only the S3 buckets that match the specified tags.

        Args:
            tags (dict[str, str] | None): A dictionary containing tag key-value pairs for filtering.
                                        If None, all buckets are returned.

        Returns:
            list[dict]: A list of dictionaries containing information of each S3 bucket.
        """
        logger.info(f"Retrieving S3 buckets from AWS account {self.account_id}{f', with tags {tags}' if tags else ''}")
        response = self.client.list_buckets()
        buckets = []

        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            if tags:
                try:
                    tag_response = self.client.get_bucket_tagging(Bucket=bucket_name)
                    bucket_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
                    if all(bucket_tags.get(key) == value for key, value in tags.items()):
                        buckets.append(bucket)
                except self.client.exceptions.ClientError as e:
                    # Skip buckets without tags or access issues
                    logger.warning(f"Could not retrieve tags for bucket {bucket_name}: {e}")
                    continue
            else:
                buckets.append(bucket)

        return buckets

    def get_all_s3_buckets(self, tags: dict[str, str] | None = None) -> list[S3Bucket]:
        """Retrieve a list of all S3 buckets as S3Bucket objects, including name, creation date, and account ID. optionally filtering by tags.

        If tags are provided, only buckets with the specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing tag key-value pairs for filtering.
                                        If None, all buckets are returned.

        Returns:
            list[S3Bucket]: A list of S3Bucket objects representing the S3 buckets in the account.
        """
        raw_buckets = self.get_all_s3_buckets_raw(tags)
        s3_buckets = [
            S3Bucket(
                name=bucket['Name'],
                creation_date=datetime_to_iso8601(bucket['CreationDate']),
                account_id=settings.app.aws_account.aws_account_id
            )
            for bucket in raw_buckets
        ]
        return s3_buckets

    def delete_bucket(self, bucket_name: str):
        """Delete S3 bucket from AWS"""
        res = self.client.delete_bucket(Bucket=bucket_name)
        logger.info(f"Delete Bucket {bucket_name} response: {res}")

    def delete_all_objects_in_bucket(self, bucket_name: str) -> None:
        """Delete all files/folders in the S3 bucket"""
        resp = self.client.list_objects(Bucket=bucket_name)
        if 'Contents' in resp:
            files_to_delete = [{"Key": c['Key']} for c in resp['Contents']]
            self.client.delete_objects(
                Bucket=bucket_name,
                Delete={
                    'Objects': files_to_delete
                }
            )
            logger.info(f"Files deleted: {files_to_delete} in the bucket {bucket_name}")

    def get_texts_in_all_log_files_inside_folder(self, bucket_name: str, folder_name: str) -> str:
        """
        Function to get all texts in log files stored in a folder inside a bucket
        :param bucket_name: The name of the bucket
        :param folder_name: The name of the folder inside the bucket
        :return: A string contains all log messages
        """
        logger.info(f"Getting all texts in log files inside {bucket_name}/{folder_name} ")
        paginator = self.client.get_paginator('list_objects_v2')
        response_iterator = paginator.paginate(Bucket=bucket_name, Prefix=folder_name)
        text = ''
        for page in response_iterator:
            for item in page['Contents']:
                key = item['Key']
                response = self.client.get_object(Bucket=bucket_name, Key=key)
                log_text = response['Body'].read().decode('utf-8')
                text += log_text
        return text

    def delete_all_files_in_folder(self, bucket_name: str, folder_name: str) -> None:
        """
        Function to clean up a folder inside a bucket
        :param bucket_name: Name of the bucket
        :param folder_name: Name of the folder inside the bucket
        """
        logger.info("delete_all_files_in_folder()")
        response = self.client.list_objects_v2(Bucket=bucket_name, Prefix=folder_name)
        if 'Contents' in response:
            objects_to_delete = [{'Key': obj['Key']} for obj in response['Contents']]
            response = self.client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects_to_delete})

    def get_bucket_folder_info(self, bucket_name: str) -> dict:
        """
        Function to call boto3.client to get folders, and files inside each folder in a bucket in S3
        :param bucket_name: name of bucket in S3
        :return: A dictionary contains folder_names as keys, and elements inside each folder as values
        """
        logger.info(f'get_bucket_folder_info(), {bucket_name=}')
        objects = []
        paginator = self.client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects.extend(page['Contents'])
        response = self.client.list_objects_v2(Bucket=bucket_name, Delimiter='/')
        folder_names = []
        folder_information = collections.defaultdict(list)
        for prefix in response.get('CommonPrefixes', []):
            folder_names.append(prefix.get('Prefix').rstrip('/'))
        logger.info(f"Folder inside {bucket_name}: {folder_names}")
        for object in objects:
            for folder_name in folder_names:
                if object['Key'].startswith(folder_name):
                    folder_information[folder_name].append(object['Key'])
        return folder_information

    def get_latest_file(self, bucket_name: str, folder_name: str) -> str:
        """
        Function to get the latest log file generated inside the folder in a bucket
        :param bucket_name: The bucket the folder exists inside
        :param folder_name: The folder this function will search
        :return: The path of the latest log file inside the folder
        """
        logger.info(f'get_latest_file(), {bucket_name=}, {folder_name=}')
        response = self.client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=folder_name
        )
        latest_file = sorted(response['Contents'], key=itemgetter('LastModified'), reverse=True)[0]['Key']
        return latest_file

    def delete_file(self, bucket_name: str, file_path: str) -> None:
        """
        Delete a file inside a folder in a bucket
        :param bucket_name: Name of bucket in S3
        :param file_path: path to the file
        """
        logger.info(f'delete_file(), {bucket_name=}, {file_path=}')
        response = self.client.delete_object(
            Bucket=bucket_name,
            Key=file_path
        )
        logger.debug(f"Delete file response: {response}")

    def get_number_of_files(self, bucket_name: str, folder_name: str) -> int:
        """
        Function to get the number of existing files inside a folder in a bucket
        :param bucket_name: The bucket the folder exists inside
        :param folder_name: The folder this function will search
        :return: The number of files inside the folder
        """
        logger.info(f'get_number_of_files(), {bucket_name=}, {folder_name=}')
        response = self.client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=folder_name
        )
        file_count = len(response.get('Contents', []))
        return file_count

    def wait_until_folder_found(self, bucket_name: str, folder_name: str, timeout: int = 1200) -> bool:
        """
        Function to check folder is created in a bucket
        :param bucket_name: The bucket the folder exists inside
        :param folder_name: The folder this function will search
        :raises: `TimeoutError` if there is no expected folder created in the folder after timeout
        """
        logger.info(f"Finding folder {folder_name}/ in s3 bucket {bucket_name}")
        found_folder = False
        start_time = time.monotonic()
        s3_bucket_folder_info = {}
        time_passed = 0
        while time_passed < timeout and not found_folder:
            time.sleep(60)
            time_passed = int(time.monotonic() - start_time)
            s3_bucket_folder_info = self.get_bucket_folder_info(bucket_name=bucket_name)
            if folder_name in s3_bucket_folder_info:
                found_folder = True
            elif '/' in folder_name:
                folder_prefix = folder_name.split('/')[0]
                if folder_prefix in s3_bucket_folder_info and any(folder_name in content for content in s3_bucket_folder_info[folder_prefix]):
                    found_folder = True
        if not found_folder:
            logger.debug(f"Bucket: {bucket_name}, Expected Folder: {folder_name} after {time_passed} sec")
            raise TimeoutError(f"There is no folder {folder_name} inside {bucket_name} after {time_passed} sec")
        return True

    def wait_until_at_least_one_file(self, bucket_name: str, folder_name: str, timeout: int = 600) -> None:
        """
        Function to get the number of existing files inside a folder in a bucket
        :param bucket_name: The bucket the folder exists inside
        :param folder_name: The folder this function will search
        :raises: `TimeoutError` if there is no newly created file appears in the folder after timeout
        """
        start_time = time.monotonic()
        time_passed = 0
        created = False
        while time_passed < timeout and not created:
            time.sleep(60)
            time_passed = int(time.monotonic() - start_time)
            response = self.get_number_of_files(bucket_name=bucket_name, folder_name=folder_name)
            if response > 0:
                logger.info(f"There is at least one file exsits in {bucket_name}/{folder_name}")
                created = True
        if not created:
            raise TimeoutError(f"There is no files exsit in {bucket_name}/{folder_name} after {time_passed} sec")

    def download_file(self, bucket_name: str, file_name: str, destination: str) -> None:
        """
        Function to download a file inside a bucket
        :param bucket_name: The bucket the file exists
        :param file_name: Object key
        :param destination: The destination this file to be downloaded
        """
        logger.info(f"download_file(), {bucket_name=}, {file_name=}, {destination=}")
        try:
            self.client.download_file(bucket_name, file_name, destination)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                logger.error("The object does not exist.")
            else:
                raise Exception

    def get_file_contents(self, bucket_name: str, file_path: str) -> str:
        """
        Function to get content inside the file in a folder inside a bucket
        :param bucket_name: name of bucket in S3
        :param file_path: the url of the file inside this bucket
        :return: A string contains all messages inside this file
        """
        logger.info(f'get_file_contents(), {bucket_name=}, {file_path=}')
        object_info = self.client.get_object(Bucket=bucket_name,
                                             Key=file_path)
        log_messages = object_info['Body'].read().decode('utf-8')
        return log_messages

    def assert_s3_object_content(self, file_contents: str, expected_contents: str | list[str]) -> None:
        """
        Check whether expected contents appears in the file in S3
        :param file_contents: Contents in the file
        :param expected_contents: Contents want to check
        :raises: `AssertionError` if doesn't find expected contents in the log
        """
        if type(expected_contents) is str:
            expected_contents = [expected_contents]
        for content in expected_contents:
            logger.info(f"Check if {content} appears in S3 bucket file object")
            assert content.lower() in file_contents, f'File is expected to contain at least one appearance of {content}, but found none'

    def assert_content_appear_in_log(self, bucket_name: str, folder_name: str, content: str, timeout: int = 360) -> None:
        """
        Check whether expected contents appear in any file inside the folder in the S3 bucket within timeout
        :param bucket_name: Name of the bucket
        :param folder_name: Name of the folder inside the bucket
        :param expected_contents: Contents want to check
        :raises: `TimeoutError` if there is no newly created file appears in the folder after timeout
        """
        start_time = time.monotonic()
        time_passed = 0
        found = False
        while time_passed < timeout and not found:
            time.sleep(30)
            time_passed = int(time.monotonic() - start_time)
            response = self.get_texts_in_all_log_files_inside_folder(bucket_name=bucket_name, folder_name=folder_name)
            if content in response:
                logger.info(f"Found {content} in at least one file exsits in {bucket_name}/{folder_name}")
                found = True
        if not found:
            raise TimeoutError(f"Found no appearance of {content} inside {bucket_name}/{folder_name} after {time_passed} sec")

    def get_all_file_names_inside_folder(self, bucket_name: str, folder_name: str) -> list:
        """
        Get all files inside a folder in a bucket
        :param bucket_name: Name of the bucket
        :param folder_name: Name of the folder inside the bucket
        :return: A list contains names of all files inside the folder without folder path prefix
        """
        logger.info(f'get_all_file_names_inside_folder(), {bucket_name=}, {folder_name=}')
        response = self.client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=folder_name
        )
        file_names = [file['Key'].split(folder_name)[1] for file in response['Contents']]
        return file_names

    def list_bucket(self) -> list:
        """
        Get names of all existing buckets
        :return: A list contains names of all existing buckets
        """
        response = self.client.list_buckets()
        names = [bucket['Name'] for bucket in response['Buckets']]
        return names

    def create_bucket(self, bucket_name: str, region: str) -> str:
        """
        Create a S3 bucket
        :param bucket_name: Name of the bucket that will be created, example: test-bucket
        :param region: Region that this bucket will be in
        :return: Created bucket location
        """
        response = None
        if region != "us-east-1":
            response = self.client.create_bucket(Bucket=bucket_name,
                                                 CreateBucketConfiguration={
                                                    'LocationConstraint': region
                                                 })
        else:
            response = self.client.create_bucket(Bucket=bucket_name)
        return response['Location']

    def attach_bucket_policy(self, bucket_policy: dict, bucket_name: str) -> dict:
        """
        Attach a Bucket policy to a S3 bucket
        :param bucket_policy: The Bucket policy as a JSON document to attach
        :param bucket_name: The S3 bucket
        """
        response = self.client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=bucket_policy
        )
        return response

    def check_s3_bucket_accessibility(self, bucket_name: str) -> bool:
        """
        Check if the given S3 bucket is accessible to any identity

        :param bucket_name: Name of the S3 bucket
        :return: True if this S3 bucket can be accessed by any identity, False otherwise
        """
        try:
            policy_response = self.client.get_bucket_policy(Bucket=bucket_name)
            bucket_policy = policy_response['Policy']
            if "Principal" in bucket_policy:
                logger.info("The S3 bucket is accessible by an identity through bucket policy.")
                return True
            else:
                logger.info("No identity found in the bucket policy.")

        except botocore.exceptions.ClientError as e:
            # Check if the error code is NoSuchBucketPolicy
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                logger.info("No bucket policy found for the S3 bucket.")
            else:
                logger.error(f"Error retrieving bucket policy: {e}")
                raise

        # If no policy or Principal found, check ACL
        try:
            acl_response = self.client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl_response['Grants']:
                grantee = grant['Grantee']
                if grantee['Type'] == 'CanonicalUser' or grantee['Type'] == 'Group':
                    logger.info(f"Access granted to {grantee['ID']} in the ACL.")
                    return True
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to get ACL for bucket {bucket_name}: {e}")

        return False

    def list_all_s3_buckets_that_is_accessible(self) -> list:
        """
        Return a list of S3 buckets that can be accessed by any identity

        :return: A list of S3 buckets
        """
        all_buckets = self.list_bucket()
        return list(filter(lambda bucket: self.check_s3_bucket_accessibility(bucket), all_buckets))
