package booking.app.bookingapppki.controller;

import booking.app.bookingapppki.dto.CertRequest;
import booking.app.bookingapppki.dto.CertRequestDTO;
import booking.app.bookingapppki.model.Certificate;
import booking.app.bookingapppki.model.CertificateNode;
import booking.app.bookingapppki.model.Subject;
import booking.app.bookingapppki.service.CertificateService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

@RestController
@RequestMapping("api/admin")
public class AdminController {
    @Autowired
    CertificateService certificateService;
    @GetMapping
    public ResponseEntity<ArrayList<CertificateNode>> getCertificateHierarchy() throws CertificateException, IOException, NoSuchAlgorithmException {
        return ResponseEntity.ok(certificateService.getCertificateHierarchy());
    }
    public ResponseEntity<Boolean> createIntermediateCertificate(@RequestParam String issuerSerialNumber) throws IOException {
        Certificate certificate = certificateService.createIntermediateCertificate(issuerSerialNumber);
        if(certificate!=null){
            return ResponseEntity.ok(true);
        }
        return ResponseEntity.ok(false);
    }
    @PostMapping
    public ResponseEntity<Boolean> createCertificate(@RequestParam String issuerSerialNumber, @RequestParam String id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate certificate = certificateService.createCertificate(issuerSerialNumber, id);
        if(certificate!=null){
            return ResponseEntity.ok(true);
        }
        return ResponseEntity.ok(false);
    }

    @PostMapping(value = "/request")
    public ResponseEntity<Boolean> createCertificateRequest(@RequestBody CertRequestDTO certRequestDTO) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException, PKCSException {
        Boolean status = certificateService.createCertificateRequest(certRequestDTO);
        return ResponseEntity.ok(status);
    }
}
