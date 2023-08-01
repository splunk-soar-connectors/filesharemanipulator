[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## App description

File share manipulator is an application that has the ability to manipulate files on a specific
server. After two actions get_file and put_file, the user is able to add a specific file to a
specific place, as well as download a desired file from the appropriate place.

## Add your files

-   -   [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file)
        or
        [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file)
        files

-   -   [Add files using the command
        line](https://docs.gitlab.com/ee/gitlab-basics/add-file.html#add-a-file-using-the-command-line)
        or push an existing Git repository with the following command:

<!-- -->

        
          cd
          existing_repo
          git remote add origin https://gitlab.com/splunk-fdse/phantom-advanced-poc/apps/splunkfileshare.git
          git branch -M main
          git push -uf origin main
        
      

## Installation

-   Create your Splunk instance
-   Install the app in your Splunk instance (via UI)
-   Configure an asset for your app *Apps / TopDesk / Configure New Asset* by providing:
    -   IP of your machine server
    -   Username and Application Password to authenticate at server
    -   Domain as a optional parameter

## Usage

-   Action `      get file     `
    -   share name -> Share name of service
    -   file path -> whole path to the file which we want to download from the server
-   Action `      put file     `
    -   share name -> Share name of service
    -   path -> Whole path to place where you want to have a file
    -   vault id -> Vault ID of file which you want to put from Container (Event)

## License

This project is licensed under [Splunk Pre-Release Software License
Agreement](https://gitlab.com/splunk-fdse/phantom-advanced-poc/apps/phtopdesk/-/blob/master/app/LICENSE.md)
