package com.example.farmmitra.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class BuyerController {

    @GetMapping("/buyer/dashboard")
    public String buyerDashboard() {
        return "buyer-dashboard";
    }
}