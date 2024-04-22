package booking.app.bookingapppki.repository;

import booking.app.bookingapppki.dto.CertRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface CertRequestRepository extends JpaRepository<CertRequest, UUID> {

}
