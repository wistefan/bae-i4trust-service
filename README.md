# bae-i4trust-service
BAE Plugin for i4Trust services

## Usage

Create a zip from the contents of this directory:
```shell
zip bae-i4trust-service.zip package.json i4trust_service.py
```

Copy the zip file to the `/plugins` directory of your charging backend component and load the plugin:
```shell
manage.py loadplugin plugins/i4trust_service.py
```
