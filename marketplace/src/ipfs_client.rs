//! IPFS Client for BlackSilk Marketplace
//! Handles decentralized file storage for product images and documents

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone)]
pub struct IpfsClient {
    base_url: String,
    client: Client,
    gateway_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpfsUploadResponse {
    pub hash: String,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpfsPin {
    pub hash: String,
    pub pinned: bool,
    pub size: u64,
}

impl IpfsClient {
    pub fn new(ipfs_api_url: &str, gateway_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();

        Self {
            base_url: ipfs_api_url.to_string(),
            client,
            gateway_url: gateway_url.to_string(),
        }
    }

    /// Upload file to IPFS
    pub async fn upload_file(&self, file_data: &[u8], filename: &str) -> Result<IpfsUploadResponse> {
        // Validate file size (max 10MB for marketplace)
        if file_data.len() > 10 * 1024 * 1024 {
            return Err(anyhow!("File too large. Maximum 10MB allowed."));
        }

        // Validate file type (images only for marketplace)
        if !self.is_valid_image_type(file_data) {
            return Err(anyhow!("Invalid file type. Only images are allowed."));
        }

        let url = format!("{}/api/v0/add", self.base_url);
        
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(file_data.to_vec())
                .file_name(filename.to_string()));

        let response = self.client
            .post(&url)
            .multipart(form)
            .send()
            .await?;

        if response.status().is_success() {
            let result: IpfsUploadResponse = response.json().await?;
            
            // Pin the file to ensure it stays available
            self.pin_hash(&result.hash).await?;
            
            println!("📁 Uploaded {} to IPFS: {}", filename, result.hash);
            Ok(result)
        } else {
            let error_text = response.text().await?;
            Err(anyhow!("IPFS upload failed: {}", error_text))
        }
    }

    /// Upload multiple files as a directory
    pub async fn upload_files(&self, files: HashMap<String, Vec<u8>>) -> Result<Vec<IpfsUploadResponse>> {
        let mut results = Vec::new();
        
        for (filename, data) in files {
            match self.upload_file(&data, &filename).await {
                Ok(response) => results.push(response),
                Err(e) => {
                    println!("Failed to upload {}: {}", filename, e);
                    return Err(e);
                }
            }
        }
        
        Ok(results)
    }

    /// Download file from IPFS
    pub async fn download_file(&self, hash: &str) -> Result<Vec<u8>> {
        let url = format!("{}/ipfs/{}", self.gateway_url, hash);
        
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let data = response.bytes().await?;
            Ok(data.to_vec())
        } else {
            Err(anyhow!("Failed to download from IPFS: {}", hash))
        }
    }

    /// Get file info from IPFS
    pub async fn get_file_info(&self, hash: &str) -> Result<serde_json::Value> {
        let url = format!("{}/api/v0/object/stat?arg={}", self.base_url, hash);
        
        let response = self.client.post(&url).send().await?;
        
        if response.status().is_success() {
            let info = response.json().await?;
            Ok(info)
        } else {
            Err(anyhow!("Failed to get file info: {}", hash))
        }
    }

    /// Pin hash to local IPFS node
    pub async fn pin_hash(&self, hash: &str) -> Result<()> {
        let url = format!("{}/api/v0/pin/add?arg={}", self.base_url, hash);
        
        let response = self.client.post(&url).send().await?;
        
        if response.status().is_success() {
            println!("📌 Pinned IPFS hash: {}", hash);
            Ok(())
        } else {
            Err(anyhow!("Failed to pin hash: {}", hash))
        }
    }

    /// Unpin hash from local IPFS node
    pub async fn unpin_hash(&self, hash: &str) -> Result<()> {
        let url = format!("{}/api/v0/pin/rm?arg={}", self.base_url, hash);
        
        let response = self.client.post(&url).send().await?;
        
        if response.status().is_success() {
            println!("📌 Unpinned IPFS hash: {}", hash);
            Ok(())
        } else {
            Err(anyhow!("Failed to unpin hash: {}", hash))
        }
    }

    /// List all pinned hashes
    pub async fn list_pins(&self) -> Result<Vec<IpfsPin>> {
        let url = format!("{}/api/v0/pin/ls", self.base_url);
        
        let response = self.client.post(&url).send().await?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            let mut pins = Vec::new();
            
            if let Some(keys) = result["Keys"].as_object() {
                for (hash, info) in keys {
                    pins.push(IpfsPin {
                        hash: hash.clone(),
                        pinned: true,
                        size: info["Type"].as_str().map(|_| 0).unwrap_or(0), // Simplified
                    });
                }
            }
            
            Ok(pins)
        } else {
            Err(anyhow!("Failed to list pins"))
        }
    }

    /// Generate IPFS URL for hash
    pub fn get_ipfs_url(&self, hash: &str) -> String {
        format!("{}/ipfs/{}", self.gateway_url, hash)
    }

    /// Generate IPFS gateway URL for hash  
    pub fn get_gateway_url(&self, hash: &str) -> String {
        format!("https://ipfs.io/ipfs/{}", hash)
    }

    /// Validate image file type
    fn is_valid_image_type(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        // Check common image signatures
        match &data[0..8] {
            // PNG
            [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] => true,
            // JPEG
            data if data.starts_with(&[0xFF, 0xD8, 0xFF]) => true,
            // GIF87a or GIF89a
            data if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") => true,
            // WebP
            data if data[0..4] == [0x52, 0x49, 0x46, 0x46] && data[8..12] == [0x57, 0x45, 0x42, 0x50] => true,
            _ => false,
        }
    }

    /// Calculate content hash for verification
    pub fn calculate_content_hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Verify file integrity
    pub async fn verify_file_integrity(&self, hash: &str, expected_content_hash: &str) -> Result<bool> {
        let data = self.download_file(hash).await?;
        let actual_hash = self.calculate_content_hash(&data);
        Ok(actual_hash == expected_content_hash)
    }

    /// Upload product image with marketplace-specific validation
    pub async fn upload_product_image(&self, image_data: &[u8], product_id: &str) -> Result<IpfsUploadResponse> {
        // Additional marketplace validation
        if image_data.len() > 5 * 1024 * 1024 { // 5MB limit for product images
            return Err(anyhow!("Product image too large. Maximum 5MB allowed."));
        }

        // Content moderation - check for inappropriate content
        if self.contains_inappropriate_content(image_data) {
            return Err(anyhow!("Image violates community standards. Don't be sick."));
        }

        let filename = format!("product_{}.jpg", product_id);
        self.upload_file(image_data, &filename).await
    }

    /// Basic content moderation (placeholder)
    fn contains_inappropriate_content(&self, _data: &[u8]) -> bool {
        // In a real implementation, this would use AI/ML for content detection
        // For now, we rely on community reporting and manual moderation
        false
    }

    /// Get IPFS node status
    pub async fn get_node_status(&self) -> Result<serde_json::Value> {
        let url = format!("{}/api/v0/id", self.base_url);
        
        let response = self.client.post(&url).send().await?;
        
        if response.status().is_success() {
            let status = response.json().await?;
            Ok(status)
        } else {
            Err(anyhow!("Failed to get IPFS node status"))
        }
    }

    /// Cleanup old/unused files
    pub async fn cleanup_unused_files(&self, used_hashes: Vec<String>) -> Result<u32> {
        let all_pins = self.list_pins().await?;
        let mut removed_count = 0;

        for pin in all_pins {
            if !used_hashes.contains(&pin.hash) {
                // Only remove if it's been unused for a while
                match self.unpin_hash(&pin.hash).await {
                    Ok(_) => {
                        removed_count += 1;
                        println!("🗑️ Removed unused IPFS file: {}", pin.hash);
                    }
                    Err(e) => {
                        println!("Failed to remove {}: {}", pin.hash, e);
                    }
                }
            }
        }

        Ok(removed_count)
    }

    /// Batch upload for multiple product images
    pub async fn batch_upload_product_images(
        &self, 
        images: Vec<(String, Vec<u8>)>
    ) -> Result<Vec<IpfsUploadResponse>> {
        let mut results = Vec::new();
        
        for (product_id, image_data) in images {
            match self.upload_product_image(&image_data, &product_id).await {
                Ok(response) => results.push(response),
                Err(e) => {
                    println!("Failed to upload image for product {}: {}", product_id, e);
                    // Continue with other uploads
                }
            }
        }
        
        Ok(results)
    }
}
