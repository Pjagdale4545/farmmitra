package com.example.farmmitra.Controller;

import com.example.farmmitra.dto.CropDto;
import com.example.farmmitra.model.Farmer;
import com.example.farmmitra.Repository.FarmerRepository;
import com.example.farmmitra.Service.CropService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

@Controller
public class FarmerDashboardController {

    private final FarmerRepository farmerRepository;
    private final CropService cropService;

    @Autowired
    public FarmerDashboardController(FarmerRepository farmerRepository, CropService cropService) {
        this.farmerRepository = farmerRepository;
        this.cropService = cropService;
    }

    @GetMapping("/farmer/dashboard")
    public String showDashboard(Model model, Authentication authentication) {
        String username = authentication.getName();
        Optional<Farmer> farmerOptional = farmerRepository.findByUsername(username);

        if (farmerOptional.isPresent()) {
            Farmer farmer = farmerOptional.get();
            model.addAttribute("farmer", farmer);
            model.addAttribute("crops", cropService.getCropsByFarmer(farmer));
            model.addAttribute("cropDto", new CropDto());
        } else {
            throw new UsernameNotFoundException("Farmer not found");
        }

        return "farmer-dashboard";
    }

    @PostMapping("/farmer/dashboard/add-crop")
    public String addCrop(@ModelAttribute("cropDto") CropDto cropDto, Authentication authentication) {
        String username = authentication.getName();
        Optional<Farmer> farmerOptional = farmerRepository.findByUsername(username);

        if (farmerOptional.isPresent()) {
            Farmer farmer = farmerOptional.get();
            cropService.saveCrop(cropDto, farmer);
        }

        return "redirect:/farmer/dashboard";
    }

    @PostMapping("/farmer/dashboard/delete-crop")
    public String deleteCrop(@RequestParam("cropId") Long cropId) {
        cropService.deleteCrop(cropId);
        return "redirect:/farmer/dashboard";
    }
}