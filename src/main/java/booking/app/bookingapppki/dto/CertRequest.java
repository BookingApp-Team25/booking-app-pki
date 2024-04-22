package booking.app.bookingapppki.dto;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@Setter
public class CertRequest {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    public UUID id;
    @Column(name = "name",nullable = false)
    public String name;
    @Column(name = "publickey",nullable = false, length = 1000)
    public String publicKey;
    @Column(name = "description",nullable = false)
    public String description;
    public CertRequest() {

    }

    public CertRequest(String name, String publicKey, String description){
        this.id = UUID.randomUUID();
        this.name = name;
        this.publicKey = publicKey;
        this.description = description;
    }
}
