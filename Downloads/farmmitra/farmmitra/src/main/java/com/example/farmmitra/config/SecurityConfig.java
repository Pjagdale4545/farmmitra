package com.example.farmmitra.config;

import com.example.farmmitra.Service.BuyerService;
import com.example.farmmitra.Service.FarmerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;
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
                .requestMatchers(
                    "/farmer/login", 
                    "/farmer/register", 
                    "/farmer/send-otp",
                    "/buyer/login", 
                    "/buyer/register"
                ).permitAll()
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
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .csrf(csrf -> csrf
                // ONLY ignore CSRF for specific POST requests that don't come from a form, like a REST API endpoint.
                // For form submissions, we want CSRF enabled. The previous configuration was incorrect.
                .ignoringRequestMatchers("/farmer/send-otp", "/buyer/register")
            )
            .authenticationManager(authenticationManager());

        return http.build();
    }
}