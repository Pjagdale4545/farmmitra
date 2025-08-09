package com.example.farmmitra.Service;

import com.example.farmmitra.dto.CropDto;
import com.example.farmmitra.model.Crop;
import com.example.farmmitra.model.Farmer;
import com.example.farmmitra.Repository.CropRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class CropService {

    private final CropRepository cropRepository;

    @Autowired
    public CropService(CropRepository cropRepository) {
        this.cropRepository = cropRepository;
    }

    public Crop saveCrop(CropDto cropDto, Farmer farmer) {
        Crop crop = new Crop();
        crop.setCropName(cropDto.getCropName());
        crop.setQuantity(cropDto.getQuantity());
        crop.setPricePerQuintal(cropDto.getPricePerQuintal());
        crop.setFarmer(farmer);
        crop.setCreatedAt(LocalDateTime.now());
        return cropRepository.save(crop);
    }

    public List<Crop> getCropsByFarmer(Farmer farmer) {
        return cropRepository.findByFarmer(farmer);
    }

    public void deleteCrop(Long cropId) {
        cropRepository.deleteById(cropId);
    }
}