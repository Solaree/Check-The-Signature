# Check-The-Signature
A tiny alternative to [JSC "IIT" web-widget for verifying the user's signature of the Certification Authority](https://eu.iit.com.ua/verify-widget)

Verifies Ukrainian digital signatures using UAPKI.


## Installation

### 1. Download UAPKI for Linux (latest release)

```sh
$ curl -L -o uapki-v2.0.12-linux-amd64.tar.gz https://github.com/specinfo-ua/UAPKI/releases/download/v2.0.12/uapki-v2.0.12-linux-amd64.tar.gz
```

### 2. Extract the archive

```sh
$ tar -xzf uapki-v2.0.12-linux-amd64.tar.gz
$ cd uapki-v2.0.12-linux-amd64
```

### 3. Copy the libraries to `/usr/lib` and create symlinks

```sh
$ sudo cp libuapki.so.2.0.12 libuapkic.so.2.0.12 libuapkif.so.2.0.12 /usr/lib/
$ cd /usr/lib
$ sudo ln -sf libuapki.so.2.0.12 libuapki.so
$ sudo ln -sf libuapki.so.2.0.12 libuapki.so.2
$ sudo ln -sf libuapkic.so.2.0.12 libuapkic.so
$ sudo ln -sf libuapkic.so.2.0.12 libuapkic.so.2
$ sudo ln -sf libuapkif.so.2.0.12 libuapkif.so
$ sudo ln -sf libuapkif.so.2.0.12 libuapkif.so.2
```

### 4. Update the dynamic linker cache

```sh
$ sudo ldconfig
```

---

## Running the Verification Script

1. Ensure you have **Python 3** and **pip** installed.

2. Install required Python packages:

```sh
$ pip install -r requirements.txt
```

3. Run the script:

```sh
$ python verify.py -h
usage: verify.py [-h] file [cms]

Verify PAdES or CAdES digital signatures

positional arguments:
  file        Path to the PDF (.pdf) or enveloped CMS (.p7s) signature
  cms         Path to the detached CMS (.p7s) signature (optional)

options:
  -h, --help  show this help message and exit
```

---

## Notes

* Adjust library version numbers if you download a different UAPKI version.
* The script supports verification of both **PAdES (PDF signatures)** and **CAdES (CMS signatures)** formats.
* Cached trusted certificates are automatically handled to speed up repeated verifications.
* Support for **ASN.1 parsing** and **XAdES (XML signatures)** format is planned for future releases.
