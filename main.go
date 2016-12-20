package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	notBefore, notAfter 	time.Time
	serialNumberLimit   	*big.Int
	rsaBits             	= 2048
	certDir					= "certs"
	commonName 				string
	domains 				string
	tlds 					string
	clusterHostname 		string
	localClusterHostname	string
	kubeDNSDomain			string
	hosts               	string
	serviceIpCidr			string
	expires					int
)

var localhostSubjectAltNames = []string{
	"localhost",
	"127.0.0.1",
}

var kubeSubjectAltNames = []string{
	"kubernetes",
	"kubernetes.default",
	"kubernetes.default.svc",
	"kubernetes.default.svc.cluster.local",
	"*.cluster.local",
}

type certificateConfig struct {
	isCA        bool
	caCert      *x509.Certificate
	caKey       *rsa.PrivateKey
	hosts       []string
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
}

func init() {
	flag.StringVar(&commonName, "common-name", "Kubernetes", "Certificate Common name")
	flag.StringVar(&domains, "domains", "valuphone", "Comma seperated list of domains (without tlds), to be enumerated with tld list")
	flag.StringVar(&tlds, "tlds", "com,net,org,local", "Comma seperated list of tlds to enumerate for each domain")
	flag.StringVar(&hosts, "hosts", "", "Comma-separated list of hostnames and/or IPs to generate certificates for")
	flag.StringVar(&clusterHostname, "cluster-hostname", "cluster.valuphone.com", "Cluster hostname(public)")
	flag.StringVar(&localClusterHostname, "local-cluster-hostname", "cluster.local.valuphone.com", "Cluster hostname(public)")
	flag.StringVar(&kubeDNSDomain, "kubedns-domain", "cluster.local", "The internal kubedns domain")
	flag.IntVar(&expires, "expires", 3650, "How many days from now the certificates should expire on")
	flag.StringVar(&serviceIpCidr, "service-ip-cidr", "172.17.1.0/24", "The CIDR range for kubernetes service IPs, ex: 172.17.1.0/24")

	notBefore = time.Now()
	notAfter = notBefore.Add(time.Duration(expires) * 24 * time.Hour)
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

}

func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// var ips []string
	ips := make([]string, 0)

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func main() {
	flag.Parse()

	sans := make([]string, 0)

	// add the CN
	sans = append(sans, commonName)

	// add the static localhost and kube specific names
	sans = append(sans, localhostSubjectAltNames...)

	// add the kube specific dns names but sub the correct domain name
	for _, ksan := range kubeSubjectAltNames {
		if strings.Contains(ksan, "cluster.local") {
			ksan = strings.Replace(ksan, "cluster.local", kubeDNSDomain, -1)
		}
		sans = append(sans, ksan)
	}

	// resolve all ips from clusterHostname
	cips, _ := net.LookupIP(clusterHostname)
	for _, ip := range cips {
		if ip.String() == "" {
			continue
		}
		sans = append(sans, ip.String())
	}

	// resolve all ips from localClusterHostname
	lcips, _ := net.LookupIP(localClusterHostname)
	for _, ip := range lcips {
		if ip.String() == "" {
			continue
		}
		sans = append(sans, ip.String())
	}

	// enumerate the domains list and tlds and concat them
	for _, dom := range strings.Split(domains, ",") {
		if dom == "" {
			continue
		}

		// tlds
		for _, tld := range strings.Split(tlds, ",") {
			if tld == "" {
				continue
			}
			host := fmt.Sprintf("*.%s.%s", dom, tld)
			sans = append(sans, host)
		}
	}

	// add the hosts from flags
	for _, host := range strings.Split(hosts, ",") {
		if host == "" {
			continue
		}
		sans = append(sans, host)
	}

	// add the service ip cidr range
	srvips, _ := Hosts(serviceIpCidr)

	for _, ip := range srvips {
		if ip == "" {
			continue
		}
		sans = append(sans, ip)
	}

	fmt.Printf("The following SAN's will be added to the certs: %s\n", sans)

	ensureCertDir()

	// Generate CA
	caCert, caKey, err := generateCertificate(certificateConfig{
		isCA:        true,
		// hosts:       []string{""},
		hosts: 		 sans,
		keyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		log.Fatal(err)
	}

	err = writeCert("ca", caCert, caKey)
	if err != nil {
		log.Fatal(err)
	}

	caParsedCertificates, err := x509.ParseCertificates(caCert)
	if err != nil {
		log.Fatal(err)
	}

	apiserverCert, apiserverKey, err := generateCertificate(certificateConfig{
		caCert:      caParsedCertificates[0],
		caKey:       caKey,
		hosts:       sans,
		keyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		log.Fatal(err)
	}

	err = writeCert("apiserver", apiserverCert, apiserverKey)
	if err != nil {
		log.Fatal(err)
	}

	// Generate Service Account Certificates
	serviceAccountCert, serviceAccountKey, err := generateCertificate(certificateConfig{
		caCert:   caParsedCertificates[0],
		caKey:    caKey,
		// hosts:    []string{""},
		hosts:    sans,
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	})
	if err != nil {
		log.Fatal(err)
	}

	err = writeCert("service-account", serviceAccountCert, serviceAccountKey)
	if err != nil {
		log.Fatal(err)
	}

}

func ensureCertDir() {
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
	    os.Mkdir(certDir, 0700)
	}
}


func writeCert(name string, cert []byte, key *rsa.PrivateKey) error {
	certFilename := fmt.Sprintf("%s/%s.pem", certDir, name)
	keyFilename := fmt.Sprintf("%s/%s-key.pem", certDir, name)

	certFile, err := os.Create(certFilename)
	if err != nil {
		return err
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certFile.Close()
	fmt.Printf("wrote %s\n", certFilename)

	keyFile, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	keyFile.Close()
	fmt.Printf("wrote %s\n", keyFilename)
	return nil
}

func generateCertificate(c certificateConfig) ([]byte, *rsa.PrivateKey, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: (serialNumber),
		Subject: pkix.Name{
			Organization: []string{"Kubernetes"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              c.keyUsage,
		ExtKeyUsage:           c.extKeyUsage,
		BasicConstraintsValid: true,
	}
	if c.hosts[0] != "" {
		template.Subject.CommonName = c.hosts[0]
	}

	if c.isCA {
		c.caCert = &template
		c.caKey = key
	}

	for _, h := range c.hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, c.caCert, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, nil, err
	}

	return derBytes, key, nil
}
