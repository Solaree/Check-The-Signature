import io, os, sys, time, json, ctypes, base64, requests

from lxml import etree
from asn1crypto import cms
from pyhanko.pdf_utils.reader import PdfFileReader


CACHE_FILENAME = ".cert_cache.json"
CACHE_MAX_AGE = 24 * 3600  # 24 hours
CCA_URL = "https://czo.gov.ua/download/tl/TL-UA-DSTU.xml" # Trusted list with the list of QTSPs for the use of TS within Ukraine

def load_cached_certs():
  if not os.path.exists(CACHE_FILENAME):
    return None
  if time.time() - os.path.getmtime(CACHE_FILENAME) > CACHE_MAX_AGE:
    return None
  with open(CACHE_FILENAME, "r") as f:
    data = json.load(f)
  return data.get("X509Certificates", [])

def save_certs_cache(certs):
  with open(CACHE_FILENAME, "w") as f:
    json.dump({"X509Certificates": certs, "timestamp": int(time.time())}, f)

def is_pdf_file(path):
  with open(path, 'rb') as f:
    header = f.read(5)
    return header.startswith(b"%PDF-")

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
    cms_der = contents if isinstance(contents, bytes) else contents.original_bytes
    return cms_der.rstrip(b'\x00'), buf[byte_range[0]:byte_range[0] + byte_range[1]] + buf[byte_range[2]:byte_range[2] + byte_range[3]]


if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("Usage: script.py <filename>")
    sys.exit(1)
  path = sys.argv[1]
  if is_pdf_file(path):
    print("[*] Detected: PAdES format")
    cms_der, pdf_data = extract_der_from_pdf(path)
  else:
    print("[*] Detected: CAdES format")
    cms_der, pdf_data = extract_pdf_from_der(path)

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

  if json.loads(response_str)["errorCode"]:
    print(f"[!] Verification failed: {response_str}")
    sys.exit(1)
  print(response_str)
  lib.json_free(response_ptr)

  request["method"] = "DEINIT"
  response_ptr = lib.process(json.dumps(request).encode())
  response_str = ctypes.cast(response_ptr, ctypes.c_char_p).value.decode()

  if json.loads(response_str)["errorCode"]:
    print(f"[!] Deinitialization failed: {response_str}")
    sys.exit(1)
  lib.json_free(response_ptr)