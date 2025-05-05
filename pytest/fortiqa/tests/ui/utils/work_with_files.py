"""Files methods"""
import logging
import os
import platform
import re
import requests
from bs4 import BeautifulSoup

info = logging.getLogger(__name__).info


class Files:
    @staticmethod
    def os_default_download_directory() -> str:
        """
        Get the default download directory of the current OS
        :return: directory
        """
        user_name = os.environ.get('USER') or os.environ.get('USERNAME')  # returns username, like "qium"
        current_os = platform.system()
        match current_os:
            case "Windows":
                folder_path = fr"C:\Users\{user_name}\Downloads"
            case "Linux":
                folder_path = fr"/home/{user_name}/Downloads"
            case _:
                raise ValueError(f"{current_os} not support")
        return folder_path

    def verify_file(self, prefix: str, suffix: str, folder_path=os_default_download_directory(), driver=None):
        """
        Verify if file presents in the specified directory or not.
        :param prefix: first characters in the file name
        :param suffix: file extension ("yaml", "txt", etc.)
        :param folder_path: specified folder
        :param driver: WebDriver
        :return: Path of the matched file
        """
        info(f"verify_file(), {prefix=}, {suffix=}, {folder_path=}")
        if "JENKINS_URL" in os.environ:
            return self.verify_file_in_selenoid_container(prefix, suffix, driver)
        else:
            files = os.listdir(folder_path)
            info(f"All files in the ~/Downloads folder {files=}")
            file_present = False
            file_path = ""
            for file in files:
                if re.match(fr"^{prefix}.*\.{suffix}$", file):
                    info(f"Found file {file=}")
                    file_present = True
                    file_path = os.path.join(folder_path, file)
                    break
            assert file_present, f"File {prefix}..{suffix} not found.\n {files=}"
            return file_path

    def delete_file(self, prefix: str, suffix: str, driver=None):
        """
        Delete files.
        :param prefix: first characters in the file name
        :param suffix: file extension ("yaml", "txt", etc.)
        :param driver: WebDriver
        """
        if "JENKINS_URL" in os.environ:
            self.verify_file_in_selenoid_container(prefix, suffix, driver, delete=True)
        else:
            folder_path = self.os_default_download_directory()
            info(f'Delete all the files starting with {prefix} and extension .{suffix} in {folder_path=}')
            files = os.listdir(folder_path)
            info(f'{files=}')
            for file in files:
                if re.match(fr"^{prefix}.*\.{suffix}$", file):
                    file_path = os.path.join(folder_path, file)
                    os.remove(file_path)

    @staticmethod
    def verify_file_in_selenoid_container(prefix: str, suffix: str, driver=None, delete=False):
        """
        Delete specific file in ~/Downloads folder in Selenoid container by Selenoid API.
        :param prefix: first characters in the file name
        :param suffix: file extension ("yaml", "txt", etc.)
        :param driver: WebDriver
        :param delete: True for delete the matched files
        :return: matched file
        """
        info("Get all files in the ~/Downloads folder using Selenoid API.")
        url = f"http://{os.environ['SELENOID_AGENT_IP']}:4444/download/{driver.session_id}/"
        download_files = requests.get(url)
        assert download_files.status_code == 200, f"Fail to get download files, err: {download_files.text}"
        soup = BeautifulSoup(download_files.text, 'html.parser')
        all_files = soup.find_all('a')
        if all_files:
            file_names = [single_file.get('href') for single_file in all_files]
            info(f"All files in the ~/Downloads folder {file_names=}")
        else:
            info("~/Downloads folder is empty.")
            return None

        info(f"Verify if file presents '{prefix}*{suffix}'.")
        file_present = False
        for file_name in file_names:
            # file_name is URL-encoded versions, need to make adjustment
            if re.match(fr"^{prefix.replace(' ', '%20')}.*\.{suffix}$", file_name):
                info(f"Found file {file_name=}")
                file_present = True
                if delete:
                    response = requests.delete(url + file_name)
                    assert response.status_code == 200, f"Fail to delete {file_name=}, err: {response.text}"
                    info(f"Deleted file {file_name=}")
                else:
                    response = requests.get(url + file_name)
                    assert response.status_code == 200, f"Fail to get {file_name=}, err: {response.text}"
                    return response
        if not delete:
            # File could be already deleted, skip verification
            assert file_present, f"File {prefix}..{suffix} not found.\n {file_names=}"
