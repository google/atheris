# Hall of Fame

A few of the most significant or interesting bugs found by Atheris. If you found
a bug that you believe should be included here, feel free to send a PR.

## Native Bugs

### Pillows leaking out of their cases

[Pillow](https://pillow.readthedocs.io/en/stable/) is the most popular Python
image processing library.

[CVE-2020-35653](https://github.com/python-pillow/Pillow/pull/5174) is a heap
buffer overflow that could occur when decoding a malicious PCX-format image,
because the decoder used certain "stride" size information from the image
header, without verifying that the stride didn't result in reading data outside
the image bounds.

### Ultrajson Bounds Checking

[Ultrajson](https://github.com/ultrajson/ultrajson) is a fast, drop-in
replacement to Python's built-in JSON parsing library.

Atheris has found a number of overflow vulnerabilities in Ultrajson, including an overflow of a 64k stack buffer in `objToJSON()`, an overflow of a 32k heap buffer in `JSON_EncodeObject()`, and several other memory corruption bugs.

### Core Interpreter: not-really-unicode
Under certain circumstances, passing invalid unicode to the CPython interpreter's `PyUnicode_DecodeUTF8Stateful()` would cause a `malloc()` of incorrect size rather than returning an error.

## Parsing Errors

A number of differential fuzzers have been written for Python, which can often
find parsing bugs when two libraries are designed for parsing the same grammar.

### Ultrajson and ultra-numbers

When given numbers that are too big to fit in a 64-bit integer, Ultrajson raises
an exception (whereas Python's built-in library can parse them). This is
actually
[permitted by the JSON standard](https://tools.ietf.org/html/rfc7159#section-6).
However, some too-big are decoded - but
[to the wrong numbers](https://github.com/ultrajson/ultrajson/issues/440).

### Same URL, Different Websites

The Python [idna](https://pypi.org/project/idna/) package and the native
[libidn2](https://www.gnu.org/software/libidn/#libidn2) library are both used
for converting Internationalized Domain Names (containing Unicode characters)
into the "Punycode" ASCII format actually used by DNS. Because Python has such
good Unicode support, the Python idna package does this entirely correctly;
however, libidn2 relies on older, outdated Unicode metadata tables. Libidn2
supports Unicode 11, but uses Unicode 9 tables. This conflict results in it
decoding some internationalized domain names incorrectly. [İ᷹.com](İ᷹.com), for
example. This could result in a domain name that resolves to a different website
depending on who accesses it, and (if a legitimate website ever uses such
characters), could allow someone to impersonte that website to any tool using
libidn2.

## Denial of Service errors

### Core Interpreter: Scope overload

Python offers libraries that can safely parse Python code without executing it. However, providing too many curly braces, while totally invalid, [causes exponentially increasing DoS](https://github.com/python/cpython/issues/90863) in Python 3.10.

### Infinite Pygment

Certain malicious inputs can cause infinite recursion in Pygments `get_tokens_unprocessed()` function.

## OSS-Fuzz Bugs

[These bugs](https://bugs.chromium.org/p/oss-fuzz/issues/list?groupby=Proj&colspec=ID%20Type%20Component%20Status%20Reported%20Owner%20Summary&q=%28adal%20OR%20aiohttp%20OR%20airflow%20OR%20ansible%20OR%20asn1crypto%20OR%20bleach%20OR%20bottleneck%20OR%20bs4%20OR%20charset_normalizer%20OR%20coveragepy%20OR%20croniter%20OR%20cryptography%20OR%20dask%20OR%20decorator%20OR%20digest%20OR%20ecdsa-python%20OR%20et-xmlfile%20OR%20filelock%20OR%20flask%20OR%20flask-restx%20OR%20ftfy%20OR%20g-api-auth-httplib2%20OR%20g-api-auth-library-python%20OR%20g-api-pubsub%20OR%20g-api-py-api-common-protos%20OR%20g-api-py-oauthlib%20OR%20g-api-python-client%20OR%20g-api-python-cloud-core%20OR%20g-api-python-firestore%20OR%20g-api-python-tasks%20OR%20g-api-resource-manager%20OR%20g-api-resumable-media-python%20OR%20g-api-secret-manager%20OR%20g-apis-py-api-core%20OR%20gc-iam%20OR%20gcloud-error-py%20OR%20g-cloud-logging-py%20OR%20gcp-python-cloud-storage%20OR%20glom%20OR%20g-py-bigquery%20OR%20g-py-crc32c%20OR%20grpc-py%20OR%20gunicorn%20OR%20idna%20OR%20iniconfig%20OR%20ipython%20OR%20jsmin%20OR%20jupyter_server%20OR%20kafka%20OR%20kiwisolver%20OR%20looker-sdk%20OR%20lxml%20OR%20mako%20OR%20matplotlib%20OR%20msal%20OR%20netaddr-py%20OR%20nfstream%20OR%20ntlm2%20OR%20numpy%20OR%20oauth2%20OR%20oauthlib%20OR%20olefile%20OR%20openpyxl%20OR%20oracle-py-cx%20OR%20orjson%20OR%20pandas%20OR%20paramiko%20OR%20pip%20OR%20protobuf-python%20OR%20psqlparse%20OR%20psycopg2%20OR%20pyasn1%20OR%20pycrypto%20OR%20pydateutil%20OR%20pygments%20OR%20pyjwt%20OR%20pyodbc%20OR%20pyparsing%20OR%20pyrsistent%20OR%20py-serde%20OR%20python-email-validator%20OR%20python-lz4%20OR%20python-rsa%20OR%20python-tabulate%20OR%20pytz%20OR%20pyxdg%20OR%20pyyaml%20OR%20redis-py%20OR%20requests%20OR%20retry%20OR%20scapy%20OR%20scikit-learn%20OR%20smart_open%20OR%20sqlalchemy%20OR%20sqlalchemy_jsonfield%20OR%20sqlalchemy-utils%20OR%20toml%20OR%20tqdm%20OR%20ujson%20OR%20underscore%20OR%20urllib3%20OR%20websocket-client%20OR%20xlrd%20OR%20xmltodict%20OR%20zipp%29&can=1) were found by OSS-Fuzz in Python projects via Atheris. (Access to some bugs may be restricted.)
