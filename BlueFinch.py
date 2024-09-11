#Founding only server with no security mode and security policy 
#UI and Exception handlingto be implemented


import socket
import subprocess
import pandas as pd
import ipaddress
from opcua import Client, ua
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
import datetime
from PySide6.QtWidgets import QApplication, QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PySide6.QtGui import QIcon
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


# Manage the certificate, check if a RedBee certificate is present, if not generate a new one
class CertificateHandler:

    '''
    CertificateHandler

    Description:
    The CertificateHandler class is responsible for managing the certificate used by the application. 
    It checks if a RedBee certificate is present, and if not, it generates a new one.

    Responsibilities:
    Generate a RedBee certificate if one does not exist.
    Load the existing certificate and private key.
    Provide methods for certificate generation and initialization.
    Provide a user interface for entering the organization name for certificate generation.

    Attributes:
    cert_path: Path to the certificate file.
    private_key_path: Path to the private key file.
    certificate: Stores the certificate data.
    private_key: Stores the private key data.

    Interfaces:
    generate_certificate(organization): Generates a RedBee certificate with the specified organization name.
    initialize(): Initializes the certificate handler, loading the certificate and private key if they exist.
    cert_param_ui(): Provides a user interface for entering the organization name for certificate generation.
    '''

    def __init__(self):
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Initializing..")
        self.cert_path = './Client/pki/own/cert/cert.pem'
        self.private_key_path = './Client/pki/own/private/private_key.pem'
        self.certificate = ""
        self.private_key = ""
        self.initialize()
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Initialized!")
            
    def generate_certificate(self, name="", organization="", country="", locality=""):
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Generating Certificate..")
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Create a certificate
        subject_name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
        issuer_name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
        if organization:
            subject_name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
            issuer_name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if country:
            subject_name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
            issuer_name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if locality:
            subject_name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
            issuer_name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name(subject_name_attributes))
        builder = builder.issuer_name(x509.Name(issuer_name_attributes))
        
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Add the dataEncipherment extension
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        # Serialize certificate and private key
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write certificate in ./Client/pki/own/cert/certificate.pem
        with open('./Client/pki/own/cert/cert.pem', 'wb') as f:
            f.write(cert_pem)
        self.cert_path = './Client/pki/own/cert/cert.pem'
        # Write private key in ./Client/pki/own/private/private_key.pem
        with open('./Client/pki/own/private/private_key.pem', 'wb') as f:
            f.write(private_key_pem)
        self.private_key_path = './Client/pki/own/private/private_key.pem'
        print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Certificate and private key generated!")
        #return cert_pem, private_key_pem
        return certificate, private_key

    def initialize(self):
        if (not os.path.exists("./Client/pki/own/private/private_key.pem")) or (not os.path.exists("./Client/pki/own/cert/cert.pem")):
            try:
                name, organization, country, locality = CertificateHandler.cert_param_ui()
            except Exception as e:
                pass
            else:
                self.certificate, self.private_key = self.generate_certificate(name, organization, country, locality)
        else:
            with open(self.cert_path, 'rb') as f:
                self.certificate = x509.load_pem_x509_certificate(f.read())
            with open(self.private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            print(f"{datetime.datetime.now().strftime('%d-%m-%Y | %H:%M:%S')} | CertificateHandler: Certificate and private key loaded!")
            
    def regenerate(self):
        try:
            name, organization, country, locality = CertificateHandler.cert_param_ui()
        except Exception as e:
            pass
        else:
            if not name and not organization and not country and not locality:
                pass
            else:
                self.certificate, self.private_key = self.generate_certificate(name, organization, country, locality)
        
    @staticmethod
    def cert_param_ui():
        name, organization, country, locality = "", "", "", ""
        try:
            cert_app = QApplication.instance()
            if not cert_app:
                cert_app = QApplication(sys.argv)
            dialog = CertParamDialog()
            if dialog.exec():
                name, organization, country, locality = dialog.get_parameters()
            return name, organization, country, locality
        except Exception as e:
            #ExceptionHandler.unhandled_exception(e, "CertParameter_UI")
            pass
            
# Ask for info to generate a certificate
class CertParamDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Certificate Generation')
        self.setWindowIcon(QIcon('./Data/img/cert_ico.png'))
        name = organization = country = locality = ''

        layout = QVBoxLayout()
        
        self.name_label = QLabel('Your Name:')
        self.name_input = QLineEdit("RedBee")
        self.name_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)

        self.organization_label = QLabel('Organization Name:')
        self.organization_input = QLineEdit()
        self.organization_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.organization_label)
        layout.addWidget(self.organization_input)

        self.country_label = QLabel('Country:')
        self.country_input = QLineEdit()
        self.country_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.country_label)
        layout.addWidget(self.country_input)

        self.locality_label = QLabel('Locality:')
        self.locality_input = QLineEdit()
        self.locality_input.textChanged.connect(self.save_toggle)
        layout.addWidget(self.locality_label)
        layout.addWidget(self.locality_input)

        self.ok_button = QPushButton('OK')
        self.ok_button.clicked.connect(self.accept)
        self.ok_button.setEnabled(False)
        layout.addWidget(self.ok_button)

        self.setLayout(layout)
        
        self.setWhatsThis("This dialog allows you to input parameters for certificate generation.")
        
    def get_parameters(self):
        name = self.name_input.text()
        organization = self.organization_input.text()
        country = self.country_input.text()
        locality = self.locality_input.text()
        return name, organization, country, locality
    
    def save_toggle(self):
        if self.name_input.text():
            if self.country_input.text():
                if len(self.country_input.text()) == 2:
                    self.ok_button.setEnabled(True)
                else:
                    self.ok_button.setEnabled(False)
            else:
                self.ok_button.setEnabled(True)
        else:
            self.ok_button.setEnabled(False)
            
class OpcScanner:
    def __init__(self):
        self.devices = pd.DataFrame()
                     
    # Get the IP address and network name of the network card of the PC
    @staticmethod    
    def get_local_ip_address():
        net_interfaces = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
        net_interfaces.append("127.0.0.1")
        net_interfaces_names = [socket.gethostbyaddr(ip)[0] for ip in net_interfaces]
        net_interfaces_names[-1] = "localhost"
        netmasks = []
        for ip in net_interfaces:
            netmask = OpcScanner.get_subnet_mask(ip)
            netmasks.append(netmask)
    
        return net_interfaces, netmasks, net_interfaces_names
    
    # Get the subnet mask of the network card of the PC
    @staticmethod
    def get_subnet_mask(ip):
        try:
            # Run the command to get network interface information
            cmd = "ipconfig" if sys.platform.startswith("win") else "ifconfig"
            output = subprocess.check_output(cmd, universal_newlines=True)
    
            # Parse the output to find the subnet mask for the given IP
            lines = output.splitlines()
            interface = None
            for line in lines:
                if ip in line:
                    interface = line.split(":")[0].strip()
                if interface and "Mask" in line:
                    subnet_mask = line.split(":")[-1].strip()
                    return subnet_mask
            return ""
        except Exception as e:
            print(f"Error retrieving subnet mask for {ip}: {e}")
            return ""
        
    # Scan the network to find the IP addresses of the devices with OPC UA servers
    def scan_network(self, ip_address, netmask):
        network = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)
        devices = []
        with ThreadPoolExecutor(max_workers=1000) as executor:
            futures = [executor.submit(OpcScanner.get_server_info, ip) for ip in network.hosts() if (ip != ipaddress.ip_address(ip_address)) and "127.0.0." not in str(ip)]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    devices.extend(result)
        localhost_result = OpcScanner.get_server_info(ipaddress.ip_address("127.0.0.1"))
        if localhost_result is not None:
            devices.extend(localhost_result)
        if len(devices) == 0:
            print(f"No devices with OPC UA servers found on the network {str(network)}")
            pass
        else:
            print(f"Found {len(devices)} devices with OPC UA servers on the network {str(network)}")
            return pd.DataFrame(devices)
    
    # Function to get server info
    def get_server_info(ip, port_min=4840, port_max=4840):
        servers_info = []
        security_modes = ["None", "Sign", "SignAndEncrypt"]
        security_policies = ["None","Basic256", "Basic128Rsa15", "Basic256Sha256"]

        if port_min == port_max:
            port = port_min
            

    #for security_mode in security_modes:
        #for security_policy in security_policies:
            try:
                with Client(f"opc.tcp://{ip}:{port}/freeopcua/server/", timeout=5) as client:
                    #client.set_security_string(f"{security_policy}, {security_mode}, {cert_handler.cert_path}, {cert_handler.private_key_path}")
                    print(f"Connected to {str(ip)}")
                    endpoints = client.get_endpoints()
                    for endpoint in endpoints:
                        server_info = {
                            "IP Address": str(ip),
                            "Endpoint URL": endpoint.EndpointUrl,
                            "Security Level": endpoint.SecurityLevel,
                            "Security Mode URI": endpoint.SecurityMode,
                            "Security Policy URI": endpoint.SecurityPolicyUri,
                            "Transport Profile URI": endpoint.TransportProfileUri
                        }
                        servers_info.append(server_info)
                return servers_info
            except Exception as e:
                print(f"Could not connect to {str(ip)}: {str(e)}")
        


        else:
            for port in [port_min, port_max]:
                try:
                    with Client(f"opc.tcp://{ip}:{port}/freeopcua/server/") as client:
                        print(f"Connected to {str(ip)}")
                        endpoints = client.get_endpoints()
                        for endpoint in endpoints:
                            server_info = {
                                "IP Address": str(ip),
                                "Endpoint URL": endpoint.EndpointUrl,
                                "Security Level": endpoint.SecurityLevel,
                                "Security Mode URI": endpoint.SecurityMode,
                                "Security Policy URI": endpoint.SecurityPolicyUri,
                                "Transport Profile URI": endpoint.TransportProfileUri
                            }
                            servers_info.append(server_info)
                    return servers_info
                except Exception as e:
                    print(f"Could not connect to {str(ip)}: {str(e)}")
            

    def main(self):
        devices = pd.DataFrame()
        ip_addresses, subnet_mask, names = OpcScanner.get_local_ip_address()
        print(f"IP Addresses: {ip_addresses}, Subnet Masks: {subnet_mask}, Network Names: {names}")
        with ThreadPoolExecutor(max_workers=len(ip_addresses)) as executor:
            futures = [executor.submit(self.scan_network, ip_addresses[i], subnet_mask[i]) for i in range(0, len(ip_addresses)-1)]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    devices = devices._append(result, ignore_index=True)
            if len(devices) == 0:
                print("No devices with OPC UA servers found on the network")
            else:
                print(f"Found {len(devices)} devices with OPC UA servers available on the network")
                df = pd.DataFrame(devices)
                print(df)
                df.to_csv("opcua_servers.csv", index=False)

# Main function
if __name__ == "__main__":
    cert_handler = CertificateHandler()
    scanner = OpcScanner()
    scanner.main()
            