package booking.app.bookingapppki.repository;

import booking.app.bookingapppki.model.Issuer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Component;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;

@Component
public class KeyStoreReader {
    private KeyStore keyStore;

    public KeyStoreReader() {
        try {
            keyStore = KeyStore.getInstance("JKS", "SUN");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public Issuer readIssuerFromStore(String alias, char[] password) {
        String keyStoreFile = "src/main/resources/keystore/keystore.jks";
        try {
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            keyStore.load(in, password);
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            String serialNumber = String.valueOf(cert.getSerialNumber());
            PrivateKey privateKey = readPemFile(serialNumber);
            X500Name issuerName = new JcaX509CertificateHolder((X509Certificate) cert).getSubject();
            return new Issuer(privateKey, cert.getPublicKey(), issuerName);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public java.security.cert.Certificate readCertificate(String keyStorePass, String alias) {
        String keyStoreFile = "src/main/resources/keystore/keystore.jks";
        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            ks.load(in, keyStorePass.toCharArray());

            if(ks.isKeyEntry(alias)) {
                Certificate cert = ks.getCertificate(alias);
                return cert;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private PrivateKey readPemFile(String serialNumber) throws Exception {
        String pemFilePath = "src/main/resources/privateKeys/" + serialNumber + ".pem";

        try (PEMParser pemParser = new PEMParser(new FileReader(pemFilePath))) {
            Object pemObject;
            while ((pemObject = pemParser.readObject()) != null) {
                if (pemObject instanceof PEMKeyPair) {
                    PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                    return converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
                }
            }
            throw new IllegalArgumentException("No private key found in PEM file");
        }
    }

    public ArrayList<X509Certificate> getAllCertificates(char[] password) throws IOException, CertificateException, NoSuchAlgorithmException {
        String keyStoreFile = "src/main/resources/keystore/keystore.jks";
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
        keyStore.load(in, password);
        ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                if (keyStore.isCertificateEntry(alias)) {
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    certificates.add(cert);
                }
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return  certificates;
    }
}


