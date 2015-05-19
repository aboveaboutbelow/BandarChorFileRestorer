Purpose
-------

Restores the file signatures in files encrypted by [BandarChor](https://www.f-secure.com/weblog/archives/00002795.html) cryptolocker malware.


Usage
-----

Install Python 3 from: https://www.python.org/downloads/

Run the script and it will search from the current directory. (If file associations are not set up, right-click the script, 'Open With', and select Python.)

The script will automatically identify affected files by the suffix. Recognised forms include: ".id-1029384756_fudx@lycos.com", ".id-6574839201_europay@india.com", and ".id-7465839201_fud@lycos.com" (where the number is any 10-digit string).

The script can be run with a target directory:

> scraper [TARGET_DIR]


The directory will be recursively searched for files with the given suffix and patched if there is any recoverable content. The original files are not modified but copied with the prefix 'CORRUPT__'. A recovery log will be saved to FileRestorer.log.


Explanation
-----------

The malware only encrypts up to 30,000 bytes of a file. The first 4 bytes identify the number of encrypted bytes. (The encryption used is strong, possibly AES-256. Recovery is not possible without the key which it appears is retrieved from the attacker's server and not persisted to disk.)

This script restores the file's extension and the file signature (and erases the encrypted bytes). This can make recovery easier. The percentage of recovered data is reported to identify files most likely to have usable data. Files with no recoverable data will be skipped.

Note: The first 4 bytes of the encrypted file are appended to the end of the file and replaced with the size. The file is truncated to account for that.

Analysis
--------

See https://github.com/tamamshud/BandarChor_CryptoLocker_Analysis

Targeted Files
--------------

BandarChor targets files in user directories with these extensions:

.113, .1cd, .3gp, .73b, .a3d, .abf, .abk, .accdb, .arj, .as4, .asm, .asvx, .ate, .avi, .bac, .bak, .bck, .bkf, .cdr, .cer, .cpt, .csv, .db3, .dbf, .doc, .docx, .dwg, .erf, .fbf, .fbk, .fbw, .fbx, .fdb, .gbk, .gho, .gzip, .iv2i, .jpeg, .jpg, .key, .keystore, .ldf, .m2v, .m3d, .max, .mdb, .mkv, .mov, .mpeg, .nbd, .nrw, .nx1, .odb, .odc, .odp, .ods, .odt, .old, .orf, .p12, .pdf, .pef, .ppsx, .ppt, .pptm, .pptx, .pst, .ptx, .pwm, .pz3, .qic, .r3d, .rar, .raw, .rtf, .rwl, .rx2, .sbs, .sldasm, .sldprt, .sn1, .sna, .spf, .sr2, .srf, .srw, .tbl, .tib, .tis, .txt, .wab, .wps, .x3f, .xls, .xlsb, .xlsk, .xlsm, .xlsx, .zip
