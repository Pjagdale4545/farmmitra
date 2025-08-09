package com.example.farmmitra.Service;

import com.example.farmmitra.dto.UserRegistrationDto;
import com.example.farmmitra.model.Buyer;
import com.example.farmmitra.Repository.BuyerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class BuyerService implements UserDetailsService {

    private final BuyerRepository buyerRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public BuyerService(BuyerRepository buyerRepository, @Lazy BCryptPasswordEncoder passwordEncoder) {
        this.buyerRepository = buyerRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Registers a new buyer by checking for existing username/email,
     * encoding the password, and saving the new buyer to the database.
     * @param registrationDto The DTO containing the registration data.
     * @return A message indicating the result of the registration.
     */
    public String registerBuyer(UserRegistrationDto registrationDto) {
        // 1. Check if username or email already exists
        if (buyerRepository.findByUsername(registrationDto.getUsername()).isPresent()) {
            return "Username already exists.";
        }
        if (buyerRepository.findByEmail(registrationDto.getEmail()).isPresent()) {
            return "Email already registered.";
        }

        // 2. Hash the password
        String encodedPassword = passwordEncoder.encode(registrationDto.getPassword());

        // 3. Create a new Buyer entity
        Buyer buyer = new Buyer(
            registrationDto.getFullName(),
            registrationDto.getUsername(),
            registrationDto.getEmail(),
            encodedPassword,
            "BUYER" // Assign "BUYER" role
        );

        // 4. Save the buyer to the database
        buyerRepository.save(buyer);
        return "Registration successful!";
    }

    /**
     * Loads user details for Spring Security authentication.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return buyerRepository.findByUsername(username)
            .map(buyer -> new User(
                buyer.getUsername(),
                buyer.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + buyer.getRole().toUpperCase()))
            ))
            .orElseThrow(() -> new UsernameNotFoundException("Buyer not found with username: " + username));
    }
}