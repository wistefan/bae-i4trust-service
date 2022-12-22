# bae-i4trust-service
BAE Plugin for services, using role-based verifiable credentials.

## Usage

Create a zip from the contents of this directory:
```shell
zip bae-vc-service.zip package.json i4trust_service.py
```
Alternatively download the zip file created with the release here on GitHub.

Copy the zip file to the `/plugins` directory of your charging backend component and load the plugin:
```shell
./manage.py loadplugin plugins/bae-vc-service.zip
```
