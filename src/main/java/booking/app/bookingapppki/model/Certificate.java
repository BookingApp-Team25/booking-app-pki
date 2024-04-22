package booking.app.bookingapppki.model;

import booking.app.bookingapppki.dto.CertRequest;
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
public class Certificate {
    private Subject subject;
    private Issuer issuer;
    private Date startDate;
    private Date endDate;
    private String serialNumber;
    private CertType type;

    // svi prethodni podaci mogu da se izvuku i iz X509Certificate, osim privatnog kljuca issuera
    public X509Certificate x509Certificate;
}
