package com.example.farmmitra.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        for (GrantedAuthority grantedAuthority : authorities) {
            if (grantedAuthority.getAuthority().equals("ROLE_BUYER")) {
                response.sendRedirect(request.getContextPath() + "/buyer/dashboard");
                return;
            } else if (grantedAuthority.getAuthority().equals("ROLE_FARMER")) {
                response.sendRedirect(request.getContextPath() + "/farmer/dashboard");
                return;
            }
        }
        // Fallback if no specific role matches (should ideally not happen with defined roles)
        response.sendRedirect(request.getContextPath() + "/"); // Redirect to home page as a fallback
    }
}