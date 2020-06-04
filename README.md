## Install Dependencies
```bash
$ pip install boto3 argparse
```

## Examples
### Store
```bash
$ echo "Hello World!" | python3 hash-obj.py store -e http://${my_endpoint} -a ${access_key} -s ${secret_key}
sha1-{hex-string}
```
### Load
```bash
$ echo "sha1-{hex-string}" | python3 hash-obj.py load -e http://${my_endpoint} -a ${access_key} -s ${secret_key}
Hello World!
```
