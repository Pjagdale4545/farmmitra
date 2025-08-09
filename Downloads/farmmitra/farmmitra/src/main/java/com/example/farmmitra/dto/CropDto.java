package com.example.farmmitra.dto;

import java.math.BigDecimal;

public class CropDto {
    private String cropName;
    private BigDecimal quantity;
    private BigDecimal pricePerQuintal;

    // Getters and setters
    public String getCropName() { return cropName; }
    public void setCropName(String cropName) { this.cropName = cropName; }
    public BigDecimal getQuantity() { return quantity; }
    public void setQuantity(BigDecimal quantity) { this.quantity = quantity; }
    public BigDecimal getPricePerQuintal() { return pricePerQuintal; }
    public void setPricePerQuintal(BigDecimal pricePerQuintal) { this.pricePerQuintal = pricePerQuintal; }
}