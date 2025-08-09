package com.example.farmmitra.Repository;

import com.example.farmmitra.model.Buyer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BuyerRepository extends JpaRepository<Buyer, Long> {
    Optional<Buyer> findByUsername(String username);
    Optional<Buyer> findByEmail(String email);
}