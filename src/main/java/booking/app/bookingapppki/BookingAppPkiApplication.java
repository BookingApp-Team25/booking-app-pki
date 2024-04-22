package booking.app.bookingapppki;

import booking.app.bookingapppki.enums.CertType;
import booking.app.bookingapppki.model.CertificateNode;
import booking.app.bookingapppki.model.Issuer;
import booking.app.bookingapppki.model.Subject;
import booking.app.bookingapppki.repository.KeyStoreReader;
import booking.app.bookingapppki.repository.KeyStoreWriter;
import booking.app.bookingapppki.service.CertificateCreator;
import booking.app.bookingapppki.service.CertificateService;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;

@SpringBootApplication
public class BookingAppPkiApplication {

	private static ApplicationContext context;
	public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {

		SpringApplication.run(BookingAppPkiApplication.class, args);



//		KeyPair keyPair = CertificateCreator.generateKeyPair();
//		X500Name x500Name = CertificateCreator.generateX500Name();
//		Issuer issuer = new Issuer(keyPair.getPrivate(), keyPair.getPublic(), x500Name);
//		KeyPair keyPair1 = CertificateCreator.generateKeyPair();
//		//X500Name x500Name1 = new X500Name("CN=John Doe1, OU=Engineering, O=Company Inc, C=US");
//		Subject subject = new Subject(keyPair1.getPublic(),x500Name);
//		CertificateCreator.generateRootCertificate(subject,issuer,new Date(),new Date());

//		KeyStoreReader keyStoreReader = new KeyStoreReader();
//		CertificateService certificateService = new CertificateService();
////		certificateService.createIntermediateCertificate("9653148");
//		ArrayList<CertificateNode> dummy = certificateService.getCertificateHierarchy();
//		System.out.println("Nesto");

	}

}
//		KeyStore keyStore = KeyStore.getInstance("JKS");
//		char[] password = "password123".toCharArray(); // Set your desired keystore password
//		keyStore.load(null, password);
//
//		// Save the empty keystore to a file
//		try (FileOutputStream fos = new FileOutputStream("src/main/resources/keystore/keystore.jks")) {
//			keyStore.store(fos, password);
//		}



