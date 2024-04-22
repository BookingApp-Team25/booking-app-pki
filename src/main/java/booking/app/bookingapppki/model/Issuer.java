package booking.app.bookingapppki.model;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.PrivateKey;
import java.security.PublicKey;
import booking.app.bookingapppki.enums.CertType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.security.PrivateKey;
import java.security.PublicKey;
@Getter
@Setter
@AllArgsConstructor
public class Issuer {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private X500Name x500Name;
}
