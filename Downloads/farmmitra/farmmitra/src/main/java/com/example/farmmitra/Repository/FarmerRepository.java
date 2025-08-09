package com.example.farmmitra.Repository;

import com.example.farmmitra.model.Farmer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface FarmerRepository extends JpaRepository<Farmer, Long> {
    Optional<Farmer> findByUsername(String username);
    
    Optional<Farmer> findByMobileNumber(String mobileNumber);

}