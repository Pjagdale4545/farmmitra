package com.example.farmmitra.Service;

import com.example.farmmitra.dto.UserRegistrationDto;
import com.example.farmmitra.model.Farmer;
import com.example.farmmitra.Repository.FarmerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.core.GrantedAuthority;


import java.util.Collections;
import java.util.Optional;

@Service
public class FarmerService implements UserDetailsService {

    private final FarmerRepository farmerRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public FarmerService(FarmerRepository farmerRepository, @Lazy BCryptPasswordEncoder passwordEncoder) {
        this.farmerRepository = farmerRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public String registerFarmer(UserRegistrationDto registrationDto) {
        // 1. Check if username or email already exists
        if (farmerRepository.findByUsername(registrationDto.getUsername()).isPresent()) {
            return "Username already exists.";
        }
       // if (farmerRepository.findByEmail(registrationDto.getEmail()).isPresent()) {
          //  return "Email already registered.";
        //}

        // 2. Hash the password
        String encodedPassword = passwordEncoder.encode(registrationDto.getPassword());

        // 3. Create a new Farmer entity
        Farmer farmer = new Farmer(
            registrationDto.getFullName(),
            registrationDto.getUsername(),
            registrationDto.getEmail(),
            encodedPassword,
            "FARMER" // Assign "FARMER" role
        );

        // 4. Save the farmer to the database
        farmerRepository.save(farmer);
        return "Registration successful!";
    }

    @Override
    public UserDetails loadUserByUsername(String mobileNumber) throws UsernameNotFoundException {
        return farmerRepository.findByMobileNumber(mobileNumber)
            .map(farmer -> new User(farmer.getMobileNumber(),
                                     farmer.getPassword(),
                                     Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + farmer.getRole()))))
            .orElseThrow(() -> new UsernameNotFoundException("Farmer with mobile number " + mobileNumber + " not found"));
    }

    // The save method is no longer needed in this service; we'll handle it in the controller.
}
