import os
import paramiko
from impacket.smbconnection import SMBConnection

from filesharemanipulator_consts import PWD


class SMB(SMBConnection):

    def __init__(self, address_ip) -> None:
        super().__init__(address_ip, address_ip)

    def connect(self, username, password, **kwrags) -> None:
        self.login(username, password)

    def get(self, file_path, file_name) -> None:
        with open(file_name, 'wb')as fh:
            self.getFile(str(PWD), file_path, fh.write)

    def put(self, remote_path, info) -> None:
        with open(info[0]['path'], 'rb') as fh:
            self.putFile(str(PWD), os.path.join(
                remote_path, info[0]['name']), fh.read)

    def close(self) -> None:
        self.logoff()


class SSH:

    def __init__(self, address_ip) -> None:
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ip = address_ip

    def connect(self, username, password, mnt_path) -> None:
        self.ssh.connect(hostname=self.ip, username=username,
                         password=password)
        self.sftp = self.ssh.open_sftp()
        self.sftp.chdir(mnt_path)

    def get(self, file_path, file_name) -> None:
        self.sftp.get(file_path, file_name)

    def put(self, remote_path, info) -> None:
        self.sftp.put(localpath=info[0]['path'], remotepath=os.path.join(
            remote_path, info[0]['name']))

    def close(self) -> None:
        self.sftp.close()
        self.ssh.close()
