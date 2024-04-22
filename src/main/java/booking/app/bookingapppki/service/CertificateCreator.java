package booking.app.bookingapppki.service;

import booking.app.bookingapppki.enums.CertType;
import booking.app.bookingapppki.model.Certificate;
import booking.app.bookingapppki.model.Issuer;
import booking.app.bookingapppki.model.Subject;
import booking.app.bookingapppki.repository.KeyStoreWriter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
@Component
public class CertificateCreator {
    public CertificateCreator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X500Name generateX500Name(){
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, String.valueOf(getSecondsSince2024()));
        builder.addRDN(BCStyle.SURNAME, "sluzba");
        builder.addRDN(BCStyle.GIVENNAME, "IT");
        builder.addRDN(BCStyle.O, "UNS-FTN");
        builder.addRDN(BCStyle.OU, "Katedra za informatiku");
        builder.addRDN(BCStyle.C, "RS");
        builder.addRDN(BCStyle.E, "itsluzba@uns.ac.rs");
        return builder.build();
    }
    public static long getSecondsSince2024() {
        LocalDateTime start = LocalDateTime.of(2024, 1, 1, 0, 0, 0);
        LocalDateTime now = LocalDateTime.now();
        long secondsSince2024 = ChronoUnit.SECONDS.between(start, now);
        return secondsSince2024;
    }
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static Certificate generateIntermediateCertificate(Issuer issuer,Date startDate, Date endDate) throws IOException {
        String serialNumber = String.valueOf(getSecondsSince2024());
        KeyPair keyPair = generateKeyPair();
        X500Name x500Name = generateX500Name();
        Subject subject = new Subject(keyPair.getPublic(),x500Name);
        Certificate certificate = generateCertificate(subject,issuer,startDate,endDate,serialNumber,CertType.INTERMEDIATE);
        String pemFileName = certificate.getSerialNumber().toString() + ".pem";
        try (PEMWriter pemWriter = new PEMWriter(new FileWriter("src/main/resources/privateKeys/" + pemFileName))) {
            pemWriter.writeObject(keyPair.getPrivate());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return certificate;
    }
    public static Certificate generateEndEntityCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate) throws IOException {
        String serialNumber = String.valueOf(getSecondsSince2024());
        return generateCertificate(subject,issuer,startDate,endDate,serialNumber,CertType.END_ENTITY);
    }
    public static Certificate generateRootCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate) throws IOException {
        String serialNumber = String.valueOf(getSecondsSince2024());
        KeyPair keyPair = generateKeyPair();
        Certificate certificate = generateCertificate(subject,issuer,startDate,endDate,serialNumber,CertType.ROOT);
        String pemFileName = certificate.getSerialNumber().toString() + ".pem";
        try (PEMWriter pemWriter = new PEMWriter(new FileWriter("src/main/resources/privateKeys/" + pemFileName))) {
            pemWriter.writeObject(keyPair.getPrivate());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return certificate;
    }
    public static Certificate generateCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber, CertType type) throws IOException {

        X509Certificate x509Certificate = generateX509Certificate(subject,issuer,startDate,endDate,serialNumber);
        Certificate certificate = new Certificate(subject,issuer,startDate,endDate,serialNumber,type, x509Certificate);
        KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
        keyStoreWriter.loadKeyStore("src/main/resources/keystore/keystore.jks",  "password123".toCharArray());
        keyStoreWriter.write(serialNumber,certificate);
        keyStoreWriter.saveKeyStore("src/main/resources/keystore/keystore.jks","password123".toCharArray());
        return certificate;
    }

    private static X509Certificate generateX509Certificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber) {
        try {
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            builder = builder.setProvider("BC");
            ContentSigner contentSigner = builder.build(issuer.getPrivateKey());
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuer.getX500Name(),
                    new BigInteger(serialNumber),
                    startDate,
                    endDate,
                    subject.getX500Name(),
                    subject.getPublicKey());

            X509CertificateHolder certHolder = certGen.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");
            return certConverter.getCertificate(certHolder);

        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }
}


