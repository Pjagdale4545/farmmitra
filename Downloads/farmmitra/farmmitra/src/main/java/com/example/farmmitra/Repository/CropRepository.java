package com.example.farmmitra.Repository;

import com.example.farmmitra.model.Crop;
import com.example.farmmitra.model.Farmer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CropRepository extends JpaRepository<Crop, Long> {
    List<Crop> findByFarmer(Farmer farmer);
}