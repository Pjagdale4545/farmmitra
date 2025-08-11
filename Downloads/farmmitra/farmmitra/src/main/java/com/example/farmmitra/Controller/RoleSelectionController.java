package com.example.farmmitra.Controller;

import com.example.farmmitra.Service.BuyerService;
import com.example.farmmitra.Service.FarmerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class RoleSelectionController {

    private final BuyerService buyerService;
    private final FarmerService farmerService;

    @Autowired
    public RoleSelectionController(BuyerService buyerService, FarmerService farmerService) {
        this.buyerService = buyerService;
        this.farmerService = farmerService;
    }

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @GetMapping("/select-role")
    public RedirectView selectRole(@RequestParam String role) {
        if ("farmer".equalsIgnoreCase(role)) {
            return new RedirectView("/farmer/login");
        } else if ("buyer".equalsIgnoreCase(role)) {
            return new RedirectView("/buyer/login");
        } else {
            return new RedirectView("/");
        }
    }
}