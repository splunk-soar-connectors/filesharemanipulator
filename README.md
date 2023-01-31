# Splunk File Share Manipulator



## App description

File share manipulator is an application that has the ability to manipulate files on a specific server. After two actions get_file and put_file, the user is able to add a specific file to a specific place, as well as download a desired file from the appropriate place.

## Add your files

- * [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- * [Add files using the command line](https://docs.gitlab.com/ee/gitlab-basics/add-file.html#add-a-file-using-the-command-line) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://gitlab.com/splunk-fdse/phantom-advanced-poc/apps/splunkfileshare.git
git branch -M main
git push -uf origin main
```
## Installation
* Create your Splunk instance i.e via Nova CO2
* Install the app in your Splunk instance (via UI)
* Configure an asset for your app *Apps / TopDesk / Configure New Asset* by providing:
    * IP of your machine server
    * Username and Application Password to authenticate at server

## Usage
* # Action `get file`
    * file path -> whole path to the file which we want to download from the server
    * protocol -> SMB or NFS

* # Action `put file`
    * path -> Whole path to place where you want to have a file
    * vault id -> Vault ID of file which you want to put from Container (Event)
    * protocol -> SMB or NFS

## License
This project is licensed under [Splunk Pre-Release Software License Agreement](https://gitlab.com/splunk-fdse/phantom-advanced-poc/apps/phtopdesk/-/blob/master/app/LICENSE.md)
