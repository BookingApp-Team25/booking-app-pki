package booking.app.bookingapppki.model;

import java.math.BigInteger;
import java.util.ArrayList;

public class CertificateNode {
    public BigInteger serialNumber;
    public CertificateNode parent;
    public ArrayList<CertificateNode> children;

    public CertificateNode(){
        children = new ArrayList<>();
    }

}
