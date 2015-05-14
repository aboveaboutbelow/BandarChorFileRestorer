
Purpose
-------

Restores the file signatures in files encrypted by [BandarChor](https://www.f-secure.com/weblog/archives/00002795.html) cryptolocker malware.


Usage
-----

Set the suffix in the script (e.g. ".id-1029384756_fudx@lycos.com") and call it with the target dir:

> scraper [TARGET_DIR]


The directory will be recursively searched for files with the given suffix and patched if there is any recoverable content. The original files are not modified but copied with the prefix 'CORRUPT__'.


Explanation
-----------

The malware only encrypts up to 30,000 bytes of a file. The first 4 bytes identify the number of encrypted bytes. (The encryption used is strong, possibly AES-256. Recovery is not possible without the key which it appears is retrieved from the attacker's server and not persisted to disk.)

This script restores the file's extension and the file signature (and erases the encrypted bytes). This can make recovery easier. The percentage of recovered data is reported to identify files most likely to have usable data. Files with no recoverable data will be skipped.

Note: The first 4 bytes of the encrypted file are appended to the end of the file and replaced with the size. The file is truncated to account for that.
