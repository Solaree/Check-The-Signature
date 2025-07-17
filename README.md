# Check-The-Signature
A tiny alternative to [JSC "IIT" web-widget for verifying the user's signature of the Certification Authority](https://eu.iit.com.ua/verify-widget)

Verify PAdES and CAdES digital signatures using DSTU 4145-2002.


## Installation

### 1. Download [UAPKI](https://github.com/specinfo-ua/UAPKI) for Linux (latest release)

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

Verify PAdES and CAdES digital signatures using DSTU 4145-2002

positional arguments:
  file        Path to the PDF (.pdf) or enveloped CMS (.p7s) signature
  cms         Path to the detached CMS (.p7s) signature (optional)

options:
  -h, --help  show this help message and exit
```

## Example output

```
[*] Detected: CAdES format (detached)
[*] Fetching certificates from Central Certification Authority...
[*] Found 298 certificate(s) within CCA
[*] Signature verification successful
[*] Subject:
  common_name = Дія Надія Володимирівна
  surname = Дія
  given_name = Надія Володимирівна
  serial_number = TINUA-1234567890
  country_name = UA
[*] Issuer:
  organization_name = ДП "ДІЯ"
  common_name = "Дія". Кваліфікований надавач електронних довірчих послуг
  serial_number = UA-43395033-1000
  country_name = UA
  locality_name = Київ
  organization_identifier = NTRUA-43395033
[*] Signing Time: 2025-08-24 00:00:00
[*] Signature Algorithm: Dstu4145WithGost34311pb
[*] Signature Format: CAdES-BES
```

---

## Notes

* Adjust library version numbers if you download a different UAPKI version.
* Cached trusted certificates are automatically handled to speed up repeated verifications.
* Support for the **signed protocol for the creation and verification of advanced electronic signatures**, as well as for the **XAdES (XML signatures)** format, is planned for future releases.
