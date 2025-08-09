package com.example.farmmitra.config;

import com.example.farmmitra.Service.BuyerService;
import com.example.farmmitra.Service.FarmerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager; // Import
import org.springframework.security.authentication.AuthenticationProvider; // Import
import org.springframework.security.authentication.ProviderManager; // Import
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays; // Import
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final BuyerService buyerService;
    private final FarmerService farmerService;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    public SecurityConfig(BuyerService buyerService, FarmerService farmerService,
                          CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler) {
        this.buyerService = buyerService;
        this.farmerService = farmerService;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider buyerAuthenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(buyerService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public DaoAuthenticationProvider farmerAuthenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(farmerService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Defines the AuthenticationManager bean, which combines all your AuthenticationProviders.
     * This is the recommended way to configure multiple providers.
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        List<AuthenticationProvider> providers = Arrays.asList(buyerAuthenticationProvider(), farmerAuthenticationProvider());
        return new ProviderManager(providers);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**").permitAll()
                .requestMatchers("/", "/select-role").permitAll()
                .requestMatchers("/buyer/login-register", "/buyer/register", "/farmer/login-register", "/farmer/register").permitAll()
                .requestMatchers("/perform_login").permitAll()
                .requestMatchers("/buyer/dashboard").hasRole("BUYER")
                .requestMatchers("/farmer/dashboard").hasRole("FARMER")
                .anyRequest().authenticated()
            )
            
            .formLogin(form -> form
                    .loginPage("/farmer/login") 
                    .loginProcessingUrl("/perform_login")
                    .successHandler(customAuthenticationSuccessHandler)
                    .failureUrl("/farmer/login?error=true")
                    .permitAll()

            		)

            .formLogin(form -> form
                .loginPage("/buyer/login-register")
                .loginProcessingUrl("/perform_login")
                .successHandler(customAuthenticationSuccessHandler)
                .failureUrl("/buyer/login-register?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/farmer/register", "/farmer/login")
            )
            // Register the custom authentication manager
            .authenticationManager(authenticationManager());

        return http.build();
        
    
            
     }
    }
