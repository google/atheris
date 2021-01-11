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

## Parsing Errors

A number of differential fuzzers have been written for Python, which can often
find parsing bugs when two libraries are designed for parsing the same grammar.

### Ultrajson and ultra-numbers

[Ultrajson](https://github.com/ultrajson/ultrajson) is a fast, drop-in
replacement to Python's built-in JSON parsing library.

When given numbers that are too big to fit in a 64-bit integer, Ultrajson raises
an exception (whereas Python's built-in library can parse them). This is
actually
[permitted by the JSON standard](https://tools.ietf.org/html/rfc7159#section-6).
However, some too-big are decoded - but
[to the wrong numbers](https://github.com/ultrajson/ultrajson/issues/440).

## Unicode Bugs

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
depending on who access it, and (if a legitimate website ever uses such
characters), could allos someone to impersonte that website to any tool using
libidn2.
