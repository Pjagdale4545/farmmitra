package com.example.farmmitra.Controller;

import com.example.farmmitra.model.Farmer;
import com.example.farmmitra.model.Role;
import com.example.farmmitra.Repository.FarmerRepository;
import com.example.farmmitra.Service.OtpService;
import com.example.farmmitra.dto.UserRegistrationDto;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.ui.Model; // Corrected import

@Controller
public class FarmerController {

    private final FarmerRepository farmerRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;

    @Autowired
    public FarmerController(FarmerRepository farmerRepository, PasswordEncoder passwordEncoder, OtpService otpService) {
        this.farmerRepository = farmerRepository;
        this.passwordEncoder = passwordEncoder;
        this.otpService = otpService;
    }

    @GetMapping("/farmer/login")
    public String showFarmerLoginPage() {
        return "farmer-login";
    }

    @GetMapping("/farmer/register")
    public String showFarmerRegisterPage(Model model) {
        // Ensure the model contains a mobileNumber attribute
      
        if (!model.containsAttribute("mobileNumber")) {
            model.addAttribute("mobileNumber", null);
        }
        
        // This is also good practice to ensure the DTO is always available
        if (!model.containsAttribute("registrationForm")) {
            model.addAttribute("registrationForm", new UserRegistrationDto());
        }

        return "farmer-register";
    }

    @PostMapping("/farmer/send-otp")
    public String sendOtp(@RequestParam("mobileNumber") String mobileNumber, RedirectAttributes redirectAttributes) {
        if (farmerRepository.findByMobileNumber(mobileNumber).isPresent()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Mobile number is already registered.");
            return "redirect:/farmer/register";
        }
        String otp = otpService.generateOtp();
        otpService.saveAndSendOtp(mobileNumber, otp);

        redirectAttributes.addFlashAttribute("message", "OTP sent to " + mobileNumber);
        redirectAttributes.addFlashAttribute("mobileNumber", mobileNumber);
        return "redirect:/farmer/register";
    }

    @PostMapping("/farmer/register")
    public String registerFarmer(@RequestParam("fullName") String fullName,
                                     @RequestParam("mobileNumber") String mobileNumber,
                                     @RequestParam("otp") String otp,
                                     RedirectAttributes redirectAttributes) {
        if (!otpService.verifyOtp(mobileNumber, otp)) {
            redirectAttributes.addFlashAttribute("errorMessage", "Invalid OTP. Please try again.");
            redirectAttributes.addFlashAttribute("mobileNumber", mobileNumber);
            return "redirect:/farmer/register";
        }
        String username = mobileNumber;
        String password = mobileNumber.substring(mobileNumber.length() - 5);
        String encodedPassword = passwordEncoder.encode(password);

        Farmer farmer = new Farmer();
        farmer.setFullName(fullName);
        farmer.setMobileNumber(mobileNumber);
       // farmer.setUsername(username);
        farmer.setPassword(encodedPassword);
        farmer.setRole(Role.FARMER);
        farmerRepository.save(farmer);

        System.out.println("SMS sent to " + mobileNumber + ": Your username is " + username + " and password is " + password);

        redirectAttributes.addFlashAttribute("message", "Registration successful! You can now log in.");
        return "redirect:/farmer/login";
    }
}