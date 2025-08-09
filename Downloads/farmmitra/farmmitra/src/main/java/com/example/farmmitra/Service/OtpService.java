package com.example.farmmitra.Service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OtpService {

    @Value("${msg91.api.key}")
    private String apiKey;

    @Value("${msg91.sender.id}")
    private String senderId;

    private final Map<String, String> otpCache = new ConcurrentHashMap<>();
    private final RestTemplate restTemplate = new RestTemplate();

    public String generateOtp() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    public void saveAndSendOtp(String mobileNumber, String otp) {
        otpCache.put(mobileNumber, otp);

        String url = UriComponentsBuilder.fromHttpUrl("https://api.msg91.com/api/v5/otp")
                .queryParam("authkey", apiKey)
                .queryParam("template_id", "YOUR_TEMPLATE_ID_HERE") 
                .queryParam("mobile", "91" + mobileNumber) 
                .queryParam("otp", otp)
                .toUriString();

        try {
            String response = restTemplate.getForObject(url, String.class);
            System.out.println("MSG91 API Response: " + response);
        } catch (Exception e) {
            System.err.println("Failed to send OTP via MSG91: " + e.getMessage());
        }
    }

    public boolean verifyOtp(String mobileNumber, String otp) {
        String storedOtp = otpCache.get(mobileNumber);
        if (storedOtp != null && storedOtp.equals(otp)) {
            otpCache.remove(mobileNumber);
            return true;
        }
        return false;
    }
}