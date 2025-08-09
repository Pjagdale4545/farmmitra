package com.example.farmmitra;

import org.springframework.boot.SpringApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; // Import this

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class FarmmitraApplication {

	public static void main(String[] args) {
		SpringApplication.run(FarmmitraApplication.class, args);
	}
   

}
