package booking.app.bookingapppki.service;

import booking.app.bookingapppki.dto.CertRequest;
import booking.app.bookingapppki.dto.CertRequestDTO;
import booking.app.bookingapppki.enums.CertType;
import booking.app.bookingapppki.model.Certificate;
import booking.app.bookingapppki.model.CertificateNode;
import booking.app.bookingapppki.model.Issuer;
import booking.app.bookingapppki.model.Subject;
import booking.app.bookingapppki.repository.CertRequestRepository;
import booking.app.bookingapppki.repository.KeyStoreReader;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Service
public class CertificateService {
    @Autowired
    private CertRequestRepository certRequestRepository;
    String keyStoreFile = "src/main/resources/keystore/keystore.jks";
    private KeyStoreReader keyStoreReader;
    public Certificate createCertificate(String issuerSerialNumber, String id) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Optional<CertRequest> certRequest1 = certRequestRepository.findById(UUID.fromString(id));
        if(certRequest1.isEmpty()){
            return null;
        }
        CertRequest certRequest=certRequest1.get();
        keyStoreReader = new KeyStoreReader();
        byte[] keyBytes = Base64.getDecoder().decode(certRequest.getPublicKey());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        Subject subject = new Subject(publicKey,new X500Name(certRequest.getName()));
        Issuer issuer=keyStoreReader.readIssuerFromStore(issuerSerialNumber,"password123".toCharArray());
        Certificate certificate = CertificateCreator.generateCertificate(subject,issuer, new Date(),new Date(2030, Calendar.DECEMBER,31),"2", CertType.INTERMEDIATE);
        return certificate;
    }
    public Certificate createIntermediateCertificate(String issuerSerialNumber) throws IOException {

        keyStoreReader = new KeyStoreReader();
        Issuer issuer=keyStoreReader.readIssuerFromStore(issuerSerialNumber,"password123".toCharArray());
        Certificate certificate = CertificateCreator.generateIntermediateCertificate(issuer, new Date(),new Date(2030, Calendar.DECEMBER,31));
        return certificate;
    }
    private X509Certificate getCertificateByName(ArrayList<X509Certificate> allCertificates, String x500Name) throws CertificateEncodingException {

        for(X509Certificate certificate : allCertificates){

            String dummy = certificate.getSubjectX500Principal().getName();
            if (Objects.equals(certificate.getSubjectX500Principal().getName(), x500Name)){
                return certificate;
            }
        }
        return null;
    }
    private CertificateNode getNodeBySerialNumber(ArrayList<CertificateNode> allNodes, BigInteger serialNumber){
        for(CertificateNode certificateNode : allNodes){
            if (certificateNode.serialNumber.equals(serialNumber)){
                return certificateNode;
            }
        }
        return null;
    }
    public ArrayList<CertificateNode> getCertificateHierarchy() throws CertificateException, IOException, NoSuchAlgorithmException {
        KeyStoreReader keyStoreReader = new KeyStoreReader();
        Set<BigInteger> serialNumberSet = new HashSet<>();
        ArrayList<X509Certificate> allCertificates = keyStoreReader.getAllCertificates("password123".toCharArray());
        ArrayList<CertificateNode> allNodes = new ArrayList<CertificateNode>();
        for(X509Certificate certificate : allCertificates){
            CertificateNode currentCertificateNode;
            if(!serialNumberSet.contains(certificate.getSerialNumber())){
                currentCertificateNode = new CertificateNode();
                currentCertificateNode.serialNumber = certificate.getSerialNumber();
                allNodes.add(currentCertificateNode);
            }
            else{
                currentCertificateNode = getNodeBySerialNumber(allNodes,certificate.getSerialNumber());
            }
            X509Certificate issuerCertificate = getCertificateByName(allCertificates,certificate.getIssuerX500Principal().getName());
            CertificateNode issuerCertificateNode;
            if(!serialNumberSet.contains(issuerCertificate.getSerialNumber())){
                issuerCertificateNode = new CertificateNode();
                issuerCertificateNode.serialNumber = issuerCertificate.getSerialNumber();
                issuerCertificateNode.children.add(currentCertificateNode);
                allNodes.add(issuerCertificateNode);
                serialNumberSet.add(issuerCertificateNode.serialNumber);
            }
            else{
                issuerCertificateNode = getNodeBySerialNumber(allNodes,issuerCertificate.getSerialNumber());
                issuerCertificateNode.children.add(currentCertificateNode);
            }
            currentCertificateNode.parent = issuerCertificateNode;

        }
        return allNodes;

    }

    public Boolean createCertificateRequest(CertRequestDTO certRequestDTO) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, OperatorCreationException, PKCSException {
        String csr = certRequestDTO.getCsr();
        //Extracting public key from CSR
        PemReader pemReader = new PemReader(new StringReader(csr));
        PemObject pemObject = pemReader.readPemObject();
        byte[] csrBytes = pemObject.getContent();
        PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(csrBytes);
        SubjectPublicKeyInfo pkInfo = certificationRequest.getSubjectPublicKeyInfo();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PublicKey publicKey = converter.getPublicKey(pkInfo);

        //Verifying digital signature
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(publicKey);
        if(certificationRequest.isSignatureValid(verifierProvider)){
            String name = certificationRequest.getSubject().toString();
            String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String description = certRequestDTO.getDescription();;
            CertRequest certRequest = new CertRequest(name,publicKeyString,description);
            certRequestRepository.save(certRequest);
            return true;
        }
        return false;
    }
}
