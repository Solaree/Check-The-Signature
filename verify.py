import io, os, sys, time, json, ctypes, base64, argparse, requests, warnings

from lxml import etree
from asn1crypto import cms
from pyhanko.pdf_utils.reader import PdfFileReader


CACHE_FILENAME = ".certs.json"
CACHE_MAX_AGE = 24 * 3600  # 24 hours
CCA_URL = "https://czo.gov.ua/download/tl/TL-UA-DSTU.xml" # Trusted list with the list of QTSPs for the use of TS within Ukraine

def load_cached_certs():
  if not os.path.exists(CACHE_FILENAME):
    return None
  try:
    with open(CACHE_FILENAME, "r") as f:
      data = json.load(f)
    timestamp = data["timestamp"]
    if timestamp is None:
      return None
    if time.time() - timestamp > CACHE_MAX_AGE:
      return None
    return data["X509Certificates"]
  except (json.JSONDecodeError, IOError):
    return None

def save_certs_cache(certs):
  with open(CACHE_FILENAME, "w") as f:
    json.dump({"X509Certificates": certs, "timestamp": int(time.time())}, f)

def is_pdf_file(path):
  with open(path, 'rb') as f:
    return f.read(4).startswith(b"%PDF")

def is_der_file(path):
  with open(path, 'rb') as f:
    return f.read(2).startswith(b"0\x82")

def extract_pdf_from_der(filename):
  with open(filename, 'rb') as f:
    cms_der = f.read()
  content_info = cms.ContentInfo.load(cms_der)
  if content_info['content_type'].native != 'signed_data':
    raise ValueError("Not a signed-data CMS")
  signed_data = content_info['content']
  eci = signed_data['encap_content_info']
  econtent = eci['content']
  if econtent is None:
    raise ValueError("No encapsulated content")
  return cms_der, econtent.native

def extract_der_from_pdf(filename, sig_index=0):
  with open(filename, 'rb') as f:
    buf = f.read()
    reader = PdfFileReader(f, strict=False)
    sigs = list(reader.embedded_signatures)
    if not len(sigs) :
      raise Exception("No embedded signatures found")
    sig = sigs[sig_index]
    contents = sig.sig_object['/Contents']
    byte_range = sig.sig_object['/ByteRange']
    if not isinstance(byte_range, list):
      byte_range = byte_range.get_object()
    byte_range = list(map(int, byte_range))
    if len(byte_range) != 4:
      raise ValueError("Invalid /ByteRange format")
    return (contents if isinstance(contents, bytes) else contents.original_bytes).rstrip(b'\x00'), buf[byte_range[0]:byte_range[0] + byte_range[1]] + buf[byte_range[2]:byte_range[2] + byte_range[3]]


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Verify PAdES or CAdES digital signatures")
  parser.add_argument("file", help="Path to the PDF (.pdf) or enveloped CMS (.p7s) signature")
  parser.add_argument("cms", nargs='?', default=None, help="Path to the detached CMS (.p7s) signature (optional)")
  args = parser.parse_args()
  file_path = args.file
  sig_path = args.cms
  file_ext = os.path.splitext(file_path)[1].lower()
  sig_ext = os.path.splitext(sig_path)[1].lower() if sig_path else None

  if sig_path:
    if file_ext != '.pdf' or not is_pdf_file(file_path):
      print("[!] In detached mode, the first argument must be a unsigned PDF")
      sys.exit(1)
    if sig_ext != '.p7s' or not is_der_file(sig_path):
      print("[!] In detached mode, the second argument must be a detached CMS signature")
      sys.exit(1)
    with open(sig_path, 'rb') as f:
      cms_der = f.read()
    with open(file_path, 'rb') as f:
      pdf_data = f.read()
    if not cms_der:
      print("[!] Failed to read CMS signature")
      sys.exit(1)
    if not pdf_data:
      print("[!] Failed to read PDF file")
      sys.exit(1)
    print("[*] Detected: CAdES format (detached)")
  else:
    if is_pdf_file(file_path):
      cms_der, pdf_data = extract_der_from_pdf(file_path)
      if not cms_der:
        print("[!] In PAdES mode, the argument must be a signed PDF")
        sys.exit(1)
      print("[*] Detected: PAdES format")
    else:
      cms_der, pdf_data = extract_pdf_from_der(file_path)
      if not pdf_data:
        print("[!] In enveloped mode, the argument must be a CMS signature with encapsulated PDF")
        sys.exit(1)
      print("[*] Detected: CAdES format (enveloped)")

  warnings.filterwarnings("ignore", category=UserWarning)

  lib = ctypes.cdll.LoadLibrary("libuapki.so")
  lib.process.argtypes = [ctypes.c_char_p]
  lib.process.restype = ctypes.c_void_p
  lib.json_free.argtypes = [ctypes.c_void_p]
  lib.json_free.restype = None

  request = {
    "method": "INIT"
  }
  response_ptr = lib.process(json.dumps(request).encode())
  response_str = ctypes.cast(response_ptr, ctypes.c_char_p).value.decode()

  if json.loads(response_str)["errorCode"]:
    print(f"[!] Initialization failed: {response_str}")
    sys.exit(1)
  lib.json_free(response_ptr)

  certs = load_cached_certs()
  if certs is None:
    print("[*] Fetching certificates from Central Certification Authority...")
    response = requests.get(CCA_URL)
    response.raise_for_status()
    buf = io.BytesIO(response.content)

    tree = etree.parse(buf)
    ns = {'tsl': tree.getroot().nsmap.get(None)}

    seen = set()
    certs = []
    for service in tree.findall('.//tsl:TSPService', namespaces=ns):
      for cert_elem in service.findall('.//tsl:X509Certificate', namespaces=ns):
        cert = cert_elem.text.strip()
        if cert not in seen:
          seen.add(cert)
          certs.append(cert)
    print(f"[*] Found {len(certs)} certificate(s) within CCA")
    save_certs_cache(certs)
  else:
    print(f"[*] Loaded {len(certs)} certificate(s) from cache")

  request["method"] = "ADD_CERT"
  request["parameters"] = {
    "certificates": certs
  }
  response_ptr = lib.process(json.dumps(request).encode())
  response_str = ctypes.cast(response_ptr, ctypes.c_char_p).value.decode()

  if json.loads(response_str)["errorCode"]:
    print(f"[!] Adding certificates failed: {response_str}")
    sys.exit(1)
  lib.json_free(response_ptr)

  request["method"] = "VERIFY"
  request["parameters"] = {
    "signature": {
      "bytes": base64.b64encode(cms_der).decode(),
      "content": base64.b64encode(pdf_data).decode()
    }
  }
  response_ptr = lib.process(json.dumps(request).encode())
  response_str = ctypes.cast(response_ptr, ctypes.c_char_p).value.decode()

  response = json.loads(response_str)
  if response["errorCode"] != 0:
    print(f"[!] Verification failed: {response_str}")
    sys.exit(1)

  sig_info = response["result"]["signatureInfos"][0]
  status = sig_info["status"]
  valid_signatures = sig_info["validSignatures"]
  valid_digests = sig_info["validDigests"]
  status_message_digest = sig_info["statusMessageDigest"]
  status_ess_cert = sig_info["statusEssCert"]
  if (
    status == "TOTAL-VALID"
    and valid_signatures
    and valid_digests
    and status_message_digest == "VALID"
    and status_ess_cert == "VALID"
  ):
    print("[*] Signature verification successful")
    # print(response_str)
    content_info = cms.ContentInfo.load(cms_der) # openssl pkcs7 [file] -inform DER -print_certs -noout
    signed_data = content_info['content']
    cert = signed_data['certificates'][0].chosen
    print_certs = lambda name, label: (
        print(f"[*] {label}:") or [
          print(f"  {attr['type'].native} = {attr['value'].native}") 
          for rdn in name.chosen 
          for attr in rdn
        ]
    )
    print_certs(cert.subject, "Subject")
    print_certs(cert.issuer, "Issuer")
    signing_time = sig_info["signingTime"] if "signingTime" in sig_info else None
    print(f"[*] Signing Time:", signing_time if signing_time else "Not available")
  else:
    print("[!] Signature verification returned warnings or errors.")
    print(f"Status: {status}")
    print(f"Valid Signatures: {valid_signatures}")
    print(f"Valid Digests: {valid_digests}")
    print(f"Status Message Digest: {status_message_digest}")
    sys.exit(1)

  lib.json_free(response_ptr)

  request["method"] = "DEINIT"
  response_ptr = lib.process(json.dumps(request).encode())
  response_str = ctypes.cast(response_ptr, ctypes.c_char_p).value.decode()

  if json.loads(response_str)["errorCode"]:
    print(f"[!] Deinitialization failed: {response_str}")
    sys.exit(1)
  lib.json_free(response_ptr)
  
