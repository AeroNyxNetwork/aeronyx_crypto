//! Optimized transport layer for mobile networks

use crate::errors::CryptoError;
use std::time::{Duration, Instant};

/// Message framing for reliable transport over WebSocket/TCP
pub struct MessageFramer {
    max_frame_size: usize,
    compression_threshold: usize,
}

impl MessageFramer {
    pub fn new() -> Self {
        Self {
            max_frame_size: 16384, // 16KB - optimal for mobile networks
            compression_threshold: 1024, // Compress if > 1KB
        }
    }
    
    /// Frame a message for transport
    pub fn frame_message(&self, data: &[u8], compress: bool) -> Result<Vec<u8>, CryptoError> {
        let mut frame = Vec::with_capacity(data.len() + 9);
        
        // Frame header: [version(1), flags(1), length(4), checksum(4)]
        frame.push(0x01); // Version 1
        
        let mut flags = 0u8;
        let payload = if compress && data.len() > self.compression_threshold {
            flags |= 0x01; // Compression flag
            compress_data(data)?
        } else {
            data.to_vec()
        };
        
        frame.push(flags);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        
        // Calculate checksum
        let checksum = calculate_checksum(&payload);
        frame.extend_from_slice(&checksum.to_be_bytes());
        
        // Add payload
        frame.extend_from_slice(&payload);
        
        Ok(frame)
    }
    
    /// Extract message from frame
    pub fn unframe_message(&self, frame: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if frame.len() < 10 {
            return Err(CryptoError::InvalidFormat("Frame too short".into()));
        }
        
        let version = frame[0];
        if version != 0x01 {
            return Err(CryptoError::InvalidFormat("Unsupported frame version".into()));
        }
        
        let flags = frame[1];
        let length = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]) as usize;
        let checksum = u32::from_be_bytes([frame[6], frame[7], frame[8], frame[9]]);
        
        if frame.len() != 10 + length {
            return Err(CryptoError::InvalidFormat("Frame length mismatch".into()));
        }
        
        let payload = &frame[10..];
        
        // Verify checksum
        if calculate_checksum(payload) != checksum {
            return Err(CryptoError::AuthenticationFailed);
        }
        
        // Decompress if needed
        if flags & 0x01 != 0 {
            decompress_data(payload)
        } else {
            Ok(payload.to_vec())
        }
    }
}

/// Network quality detector for adaptive encryption
pub struct NetworkQualityDetector {
    latency_samples: Vec<Duration>,
    bandwidth_estimates: Vec<f64>,
    last_update: Instant,
}

impl NetworkQualityDetector {
    pub fn new() -> Self {
        Self {
            latency_samples: Vec::with_capacity(10),
            bandwidth_estimates: Vec::with_capacity(10),
            last_update: Instant::now(),
        }
    }
    
    /// Add latency sample
    pub fn add_latency_sample(&mut self, latency: Duration) {
        self.latency_samples.push(latency);
        if self.latency_samples.len() > 10 {
            self.latency_samples.remove(0);
        }
        self.last_update = Instant::now();
    }
    
    /// Add bandwidth estimate (bytes per second)
    pub fn add_bandwidth_sample(&mut self, bandwidth: f64) {
        self.bandwidth_estimates.push(bandwidth);
        if self.bandwidth_estimates.len() > 10 {
            self.bandwidth_estimates.remove(0);
        }
    }
    
    /// Get recommended encryption algorithm based on network quality
    pub fn recommend_algorithm(&self) -> &'static str {
        let avg_latency = self.average_latency();
        let avg_bandwidth = self.average_bandwidth();
        
        // Use ChaCha20 for better performance on mobile/low bandwidth
        // Use AES-GCM when hardware acceleration is available and network is good
        if avg_latency < Duration::from_millis(50) && avg_bandwidth > 1_000_000.0 {
            "aes-256-gcm" // Good network, can use hardware-accelerated AES
        } else {
            "chacha20-poly1305" // Better for mobile CPUs and poor networks
        }
    }
    
    fn average_latency(&self) -> Duration {
        if self.latency_samples.is_empty() {
            return Duration::from_millis(100);
        }
        
        let sum: Duration = self.latency_samples.iter().sum();
        sum / self.latency_samples.len() as u32
    }
    
    fn average_bandwidth(&self) -> f64 {
        if self.bandwidth_estimates.is_empty() {
            return 100_000.0; // 100KB/s default
        }
        
        self.bandwidth_estimates.iter().sum::<f64>() / self.bandwidth_estimates.len() as f64
    }
}

fn calculate_checksum(data: &[u8]) -> u32 {
    use crc32fast::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn compress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)
        .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
    encoder.finish()
        .map_err(|e| CryptoError::InvalidFormat(e.to_string()))
}

fn decompress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)
        .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
    Ok(decompressed)
}
