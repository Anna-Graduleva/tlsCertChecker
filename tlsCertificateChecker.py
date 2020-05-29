"""
 Given the URL, get the SSL certificate information (Subject, Issuer, SAN, Validity)
 Get the web category of the given website (GET https://fortiguard.com/webfilter?q=<URL>)
 Pretty print the results

 This is a POC, and the full implementation should contain proper certificate verification, including:
 - Rejecting self-signed certificates
 - Host-name verification
 - Making sure that only a list of strong cipher suites is provided
 - Checking a revocation list from CRL distribution points extension in a CA certifcate
 - Verifying the expiration date
 - Using at least TLS1.2 for most security

 Alternatively, you can simply use http.client.HTTPSConnection 
 HTTPSConnection from http.client class verifies the certificate 
 Default since python version 3.4.3
"""

import sys
from OpenSSL import SSL
from OpenSSL import crypto
from socket import socket
import requests
import bs4

def print_san(x509cert):
    SAN_list = []
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            SAN_list = ext.__str__().split(", ")
    if SAN_list:
        for domain in SAN_list:
            print(domain)
    else:
        print("SAN list is empty")


def is_valid_certificate(certs):
    """expitation date, revocation list, digital signature"""
    store = crypto.X509Store()
    for i in range(1, len(certs)):
        store.add_cert(certs[i])

    storeCtx = crypto.X509StoreContext(store, certs[0])
    if storeCtx.verify_certificate() is None:
        return True
    else:
        return False


def get_web_category(host):
    response = requests.get('https://fortiguard.com/webfilter?q=' + host)
    soup = bs4.BeautifulSoup(response.text, "lxml")
    lines = soup.select('#two-column > div.col-md-9.middlecontent.col-xs-12.col-sm-12.panel-header-3 > div.padded > section > div.well > div > div > h4')
    if lines:
        return lines[0].text
    else:
        return "Cannot fetch web category"


def pretty_print_x509Name(name):
    print("CountryName: ", name.countryName)
    print("StateOrProvinceName: ", name.stateOrProvinceName)
    print("LocalityName: ", name.localityName)
    print("OrganizationName: ", name.organizationName)
    print("OrganizationalUnitName: ", name.organizationalUnitName)
    print("CommonName: ", name.commonName)
    print("EmailAddress: ", name.emailAddress)


def get_certificate_info(host):
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    conn = SSL.Connection(context, socket())
    conn.connect((host, 443))
    conn.do_handshake()
    certs = conn.get_peer_cert_chain()
    conn.close()

    if certs is None:
        print("No certificates retrieved")
    else:
        issuer = certs[0].get_issuer()
        subject = certs[0].get_subject()
        isValid = is_valid_certificate(certs)
        pretty_print_x509Name(issuer)
        pretty_print_x509Name(subject)
        print_san(certs[0])
        print(get_web_category(host))
        if isValid:
            print("Certificate is valid")
        else:
            print("Cetrificate is invalid")



if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(1)
    args = sys.argv[1:]
    host = args[0]
    print('Looking up cert info for URL: ', host)
    get_certificate_info(host)
