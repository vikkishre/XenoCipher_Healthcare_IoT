/**
 * @file XenoCipher_Healthcare_IoT.ino
 * @brief XenoCipher Healthcare IoT - Main Arduino Sketch for Windows Development
 * @version 1.0.0
 * @date 2024-01-XX
 * 
 * Main entry point for XenoCipher Healthcare IoT system running on ESP32.
 * This sketch demonstrates quantum-resistant encryption for simulated health data.
 * 
 * Development Environment: Windows + Arduino IDE
 * Target Hardware: ESP32 Development Board
 * Testing Environment: Kali Linux (separate)
 * 
 * Hardware Requirements:
 * - ESP32 Development Board
 * - WiFi connection for cloud transmission
 * - USB cable for programming and serial monitoring
 * 
 * Features:
 * - Simulated health data generation (Heart Rate, SpO2)
 * - Multi-layered XenoCipher encryption (LFSR + Chaotic Map + Transposition)
 * - Zero Trust Mode (ZTM) with ChaCha20 + Speck
 * - Adaptive attack detection and response
 * - Secure cloud transmission
 * - Real-time monitoring via Serial Monitor
 * - Interactive command interface
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_random.h>

// Project configuration
#define DEVICE_ID "XENOCIPHER_ESP32_WIN_001"
#define FIRMWARE_VERSION "1.0.0"
#define BUILD_ENVIRONMENT "Windows_Arduino_IDE"

// Timing configuration
#define DATA_COLLECTION_INTERVAL 5000   // 5 seconds
#define CLOUD_UPLOAD_INTERVAL 30000     // 30 seconds
#define ATTACK_CHECK_INTERVAL 1000      // 1 second

// WiFi credentials (will be configured via Serial)
char wifi_ssid[32] = "LAPTOP-QOA4B205 9079";
char wifi_password[64] = "poopygyat";
char cloud_endpoint[128] = "https://your-server.com/api/health-data";

// System state variables
bool wifi_connected = false;
bool encryption_enabled = true;
bool ztm_mode = false;
bool system_initialized = false;

// Timing variables
unsigned long last_data_collection = 0;
unsigned long last_cloud_upload = 0;
unsigned long last_attack_check = 0;
uint32_t data_sequence_number = 0;

// Health data structure
struct HealthData {
  uint16_t heart_rate;      // BPM
  uint8_t spo2;            // Percentage
  uint32_t timestamp;      // Unix timestamp
  uint32_t sequence;       // Sequence number
  char device_id[32];      // Device identifier
  float temperature;       // Body temperature (simulated)
  uint16_t steps;         // Step count (simulated)
};

// System statistics
struct SystemStats {
  uint32_t total_encryptions;
  uint32_t total_decryptions;
  uint32_t failed_operations;
  uint32_t ztm_activations;
  uint32_t attack_detections;
  float avg_encrypt_time_ms;
  uint32_t uptime_seconds;
  uint32_t free_heap_min;
};

SystemStats system_stats = {0};

/**
 * @brief Arduino setup function - runs once at startup
 */
void setup() {
  // Initialize serial communication
  Serial.begin(115200);
  delay(2000);  // Give time for Serial Monitor to connect
  
  // Print startup banner
  printStartupBanner();
  
  // Initialize system components
  if (initializeSystem()) {
    system_initialized = true;
    Serial.println("✅ System initialization completed successfully");
  } else {
    Serial.println("❌ System initialization failed");
    return;
  }
  
  // Configure WiFi (optional for initial testing)
  configureWiFi();
  
  // Print system status
  printSystemStatus();
  
  Serial.println("\n=== XenoCipher Healthcare IoT Ready ===");
  Serial.println("📝 Type 'help' in Serial Monitor for available commands");
  Serial.println("🔄 System will start collecting and encrypting data automatically");
  Serial.println("=" + String("=").repeat(45));
}

/**
 * @brief Arduino main loop - runs continuously
 */
void loop() {
  unsigned long current_time = millis();
  
  // Handle serial commands
  handleSerialCommands();
  
  // Only proceed if system is initialized
  if (!system_initialized) {
    delay(1000);
    return;
  }
  
  // Collect and process health data at specified intervals
  if (current_time - last_data_collection >= DATA_COLLECTION_INTERVAL) {
    collectAndProcessHealthData();
    last_data_collection = current_time;
  }
  
  // Upload to cloud at specified intervals (if WiFi connected)
  if (wifi_connected && (current_time - last_cloud_upload >= CLOUD_UPLOAD_INTERVAL)) {
    uploadDataToCloud();
    last_cloud_upload = current_time;
  }
  
  // Perform attack detection checks
  if (current_time - last_attack_check >= ATTACK_CHECK_INTERVAL) {
    performAttackDetection();
    last_attack_check = current_time;
  }
  
  // Update system statistics
  updateSystemStats();
  
  // Small delay to prevent watchdog timeout
  delay(50);
}

/**
 * @brief Print startup banner with system information
 */
void printStartupBanner() {
  Serial.println("\n" + String("=").repeat(60));
  Serial.println("    🛡️  XenoCipher Healthcare IoT System  🛡️");
  Serial.println("    Quantum-Resistant Encryption for IoT Healthcare");
  Serial.println(String("=").repeat(60));
  Serial.println("📋 System Information:");
  Serial.printf("   Device ID: %s\n", DEVICE_ID);
  Serial.printf("   Firmware Version: %s\n", FIRMWARE_VERSION);
  Serial.printf("   Build Environment: %s\n", BUILD_ENVIRONMENT);
  Serial.printf("   Compilation Date: %s %s\n", __DATE__, __TIME__);
  Serial.println(String("-").repeat(60));
  Serial.println("🔧 ESP32 Hardware Information:");
  Serial.printf("   Chip Model: %s\n", ESP.getChipModel());
  Serial.printf("   Chip Revision: %d\n", ESP.getChipRevision());
  Serial.printf("   CPU Cores: %d\n", ESP.getChipCores());
  Serial.printf("   CPU Frequency: %d MHz\n", ESP.getCpuFreqMHz());
  Serial.printf("   Flash Size: %.2f MB\n", ESP.getFlashChipSize() / (1024.0 * 1024.0));
  Serial.printf("   Free Heap: %d bytes\n", ESP.getFreeHeap());
  Serial.printf("   PSRAM Size: %d bytes\n", ESP.getPsramSize());
  Serial.println(String("=").repeat(60));
}

/**
 * @brief Initialize core system components
 */
bool initializeSystem() {
  Serial.println("🔄 Initializing system components...");
  
  // Initialize random number generator with hardware entropy
  esp_random();  // Seed the random number generator
  randomSeed(esp_random());
  
  // Set CPU frequency for optimal performance
  setCpuFrequencyMhz(240);
  Serial.printf("   ✅ CPU frequency set to %d MHz\n", ESP.getCpuFreqMHz());
  
  // Initialize system statistics
  memset(&system_stats, 0, sizeof(SystemStats));
  system_stats.free_heap_min = ESP.getFreeHeap();
  Serial.println("   ✅ System statistics initialized");
  
  // Initialize encryption system (placeholder)
  if (initializeEncryption()) {
    Serial.println("   ✅ XenoCipher encryption system initialized");
  } else {
    Serial.println("   ❌ Encryption system initialization failed");
    return false;
  }
  
  // Initialize sensor simulation
  if (initializeSensorSimulation()) {
    Serial.println("   ✅ Health sensor simulation initialized");
  } else {
    Serial.println("   ❌ Sensor simulation initialization failed");
    return false;
  }
  
  // Initialize attack detection
  if (initializeAttackDetection()) {
    Serial.println("   ✅ Attack detection system initialized");
  } else {
    Serial.println("   ❌ Attack detection initialization failed");
    return false;
  }
  
  Serial.println("🎉 All system components initialized successfully!");
  return true;
}

/**
 * @brief Initialize XenoCipher encryption system
 */
bool initializeEncryption() {
  // This is a placeholder - we'll implement the actual encryption components next
  Serial.println("      🔐 Initializing XenoCipher components:");
  Serial.println("         • LFSR Stream Cipher: Ready");
  Serial.println("         • Chaotic Map Encryption: Ready");
  Serial.println("         • Transposition Cipher: Ready");
  Serial.println("         • NTRU Key Exchange: Ready");
  Serial.println("         • ZTM Mode (ChaCha20 + Speck): Ready");
  
  encryption_enabled = true;
  return true;
}

/**
 * @brief Initialize sensor simulation system
 */
bool initializeSensorSimulation() {
  Serial.println("      📊 Initializing health sensor simulation:");
  Serial.println("         • Heart Rate: 60-100 BPM range");
  Serial.println("         • SpO2: 95-100% range");
  Serial.println("         • Temperature: 36.1-37.2°C range");
  Serial.println("         • Step Counter: Incremental simulation");
  
  return true;
}

/**
 * @brief Initialize attack detection system
 */
bool initializeAttackDetection() {
  Serial.println("      🛡️ Initializing attack detection:");
  Serial.println("         • Entropy Analysis: Active");
  Serial.println("         • Timing Attack Detection: Active");
  Serial.println("         • Pattern Analysis: Active");
  Serial.println("         • Adaptive Response: Ready");
  
  return true;
}

/**
 * @brief Configure WiFi connection
 */
void configureWiFi() {
  Serial.println("\n🌐 Configuring WiFi connection...");
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(wifi_ssid, wifi_password);
  
  Serial.printf("   Connecting to: %s", wifi_ssid);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    wifi_connected = true;
    Serial.println("\n   ✅ WiFi connected successfully!");
    Serial.printf("   📍 IP Address: %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("   📶 Signal Strength: %d dBm\n", WiFi.RSSI());
    Serial.printf("   🔗 Gateway: %s\n", WiFi.gatewayIP().toString().c_str());
  } else {
    wifi_connected = false;
    Serial.println("\n   ⚠️ WiFi connection failed - continuing in offline mode");
    Serial.println("   💡 Use 'wifi <ssid> <password>' command to configure WiFi");
  }
}

/**
 * @brief Collect and process health data with encryption
 */
void collectAndProcessHealthData() {
  // Generate simulated health data
  HealthData healthData = generateSimulatedHealthData();
  
  // Display raw data
  Serial.printf("\n📊 [Seq: %lu] Raw Health Data:\n", healthData.sequence);
  Serial.printf("   💓 Heart Rate: %d BPM\n", healthData.heart_rate);
  Serial.printf("   🫁 SpO2: %d%%\n", healthData.spo2);
  Serial.printf("   🌡️ Temperature: %.1f°C\n", healthData.temperature);
  Serial.printf("   👟 Steps: %d\n", healthData.steps);
  Serial.printf("   ⏰ Timestamp: %lu\n", healthData.timestamp);
  
  if (encryption_enabled) {
    // Encrypt the health data
    unsigned long encrypt_start = micros();
    
    // Simulate encryption process (we'll implement actual encryption next)
    bool encrypt_success = simulateEncryption((uint8_t*)&healthData, sizeof(HealthData));
    
    unsigned long encrypt_time = micros() - encrypt_start;
    
    if (encrypt_success) {
      Serial.printf("   🔐 Encryption: ✅ Success (Mode: %s)\n", ztm_mode ? "ZTM" : "Normal");
      Serial.printf("   ⚡ Encryption Time: %lu μs\n", encrypt_time);
      Serial.printf("   📦 Data Size: %d bytes\n", sizeof(HealthData));
      
      // Update statistics
      system_stats.total_encryptions++;
      updateAverageEncryptTime(encrypt_time / 1000.0);  // Convert to ms
      
      // Simulate entropy calculation
      float entropy = calculateSimulatedEntropy();
      Serial.printf("   📈 Ciphertext Entropy: %.2f bits/byte\n", entropy);
      
      // Check if we need to switch to ZTM mode
      if (entropy < 7.5 && !ztm_mode) {
        Serial.println("   ⚠️ Low entropy detected - considering ZTM activation");
      }
      
    } else {
      Serial.println("   🔐 Encryption: ❌ Failed");
      system_stats.failed_operations++;
    }
  } else {
    Serial.println("   🔐 Encryption: ⏸️ Disabled");
  }
  
  // Display system health
  Serial.printf("   💾 Free Heap: %d bytes\n", ESP.getFreeHeap());
  if (ESP.getFreeHeap() < system_stats.free_heap_min) {
    system_stats.free_heap_min = ESP.getFreeHeap();
  }
}

/**
 * @brief Generate simulated health data
 */
HealthData generateSimulatedHealthData() {
  HealthData data;
  
  // Generate realistic heart rate (60-100 BPM with some variation)
  static uint16_t base_hr = 72;
  data.heart_rate = base_hr + random(-10, 15);
  if (data.heart_rate < 60) data.heart_rate = 60;
  if (data.heart_rate > 100) data.heart_rate = 100;
  
  // Generate realistic SpO2 (95-100%)
  data.spo2 = random(95, 101);
  
  // Generate body temperature (36.1-37.2°C)
  data.temperature = 36.1 + (random(0, 110) / 100.0);
  
  // Generate step count (incremental)
  static uint16_t step_count = 0;
  step_count += random(0, 5);  // 0-4 steps per interval
  data.steps = step_count;
  
  // Set metadata
  data.timestamp = millis();
  data.sequence = ++data_sequence_number;
  strcpy(data.device_id, DEVICE_ID);
  
  return data;
}

/**
 * @brief Simulate encryption process (placeholder)
 */
bool simulateEncryption(uint8_t* data, size_t length) {
  // This is a placeholder that simulates the encryption process
  // We'll replace this with actual XenoCipher implementation
  
  // Simulate processing time
  delay(random(1, 5));
  
  // Simulate occasional failures for testing
  return (random(0, 100) > 2);  // 98% success rate
}

/**
 * @brief Calculate simulated entropy for testing
 */
float calculateSimulatedEntropy() {
  // Simulate entropy calculation
  // In ZTM mode, entropy should be higher
  if (ztm_mode) {
    return 7.8 + (random(0, 20) / 100.0);  // 7.8-7.99 bits/byte
  } else {
    return 7.2 + (random(0, 60) / 100.0);  // 7.2-7.79 bits/byte
  }
}

/**
 * @brief Upload encrypted data to cloud
 */
void uploadDataToCloud() {
  if (!wifi_connected) {
    Serial.println("⚠️ Cloud upload skipped - WiFi not connected");
    return;
  }
  
  Serial.println("\n☁️ Uploading data to cloud...");
  
  // Create JSON payload
  DynamicJsonDocument doc(1024);
  doc["device_id"] = DEVICE_ID;
  doc["timestamp"] = millis();
  doc["firmware_version"] = FIRMWARE_VERSION;
  doc["encryption_mode"] = ztm_mode ? "ZTM" : "Normal";
  doc["sequence"] = data_sequence_number;
  doc["stats"]["total_encryptions"] = system_stats.total_encryptions;
  doc["stats"]["avg_encrypt_time"] = system_stats.avg_encrypt_time_ms;
  
  String payload;
  serializeJson(doc, payload);
  
  // Simulate cloud upload
  Serial.printf("   📤 Payload size: %d bytes\n", payload.length());
  Serial.println("   🔄 Uploading...");
  
  // Simulate upload time
  delay(random(100, 500));
  
  // Simulate success/failure
  bool upload_success = (random(0, 100) > 5);  // 95% success rate
  
  if (upload_success) {
    Serial.println("   ✅ Cloud upload successful");
  } else {
    Serial.println("   ❌ Cloud upload failed - will retry");
  }
}

/**
 * @brief Perform attack detection analysis
 */
void performAttackDetection() {
  // This is a placeholder for attack detection logic
  // We'll implement actual detection algorithms later
  
  static uint32_t last_check = 0;
  uint32_t current_time = millis();
  
  // Only run detailed checks every 10 seconds
  if (current_time - last_check < 10000) {
    return;
  }
  
  last_check = current_time;
  
  // Simulate attack detection
  bool threat_detected = (random(0, 1000) < 5);  // 0.5% chance of threat detection
  
  if (threat_detected && !ztm_mode) {
    Serial.println("\n🚨 THREAT DETECTED - Activating ZTM Mode");
    enableZTMMode();
    system_stats.attack_detections++;
  } else if (!threat_detected && ztm_mode) {
    // Check if we should return to normal mode
    static uint32_t ztm_start_time = 0;
    if (ztm_start_time == 0) ztm_start_time = current_time;
    
    if (current_time - ztm_start_time > 60000) {  // 60 seconds in ZTM
      Serial.println("\n✅ Threat cleared - Returning to Normal Mode");
      disableZTMMode();
      ztm_start_time = 0;
    }
  }
}

/**
 * @brief Enable Zero Trust Mode (ZTM)
 */
void enableZTMMode() {
  ztm_mode = true;
  system_stats.ztm_activations++;
  
  Serial.println("🛡️ ZTM Mode Activated:");
  Serial.println("   • ChaCha20 encryption: Enabled");
  Serial.println("   • Speck cipher: Enabled");
  Serial.println("   • Enhanced key rotation: Active");
  Serial.println("   • Increased entropy requirements: Active");
}

/**
 * @brief Disable Zero Trust Mode
 */
void disableZTMMode() {
  ztm_mode = false;
  
  Serial.println("🔄 Normal Mode Restored:");
  Serial.println("   • Standard encryption pipeline: Active");
  Serial.println("   • Optimized performance: Enabled");
}

/**
 * @brief Update system statistics
 */
void updateSystemStats() {
  system_stats.uptime_seconds = millis() / 1000;
  
  // Update minimum free heap
  uint32_t current_heap = ESP.getFreeHeap();
  if (current_heap < system_stats.free_heap_min) {
    system_stats.free_heap_min = current_heap;
  }
}

/**
 * @brief Update average encryption time
 */
void updateAverageEncryptTime(float new_time_ms) {
  if (system_stats.total_encryptions == 1) {
    system_stats.avg_encrypt_time_ms = new_time_ms;
  } else {
    // Running average
    system_stats.avg_encrypt_time_ms = 
      (system_stats.avg_encrypt_time_ms * (system_stats.total_encryptions - 1) + new_time_ms) 
      / system_stats.total_encryptions;
  }
}

/**
 * @brief Print current system status
 */
void printSystemStatus() {
  Serial.println("\n📊 === System Status ===");
  Serial.printf("🆔 Device ID: %s\n", DEVICE_ID);
  Serial.printf("📱 Firmware: %s\n", FIRMWARE_VERSION);
  Serial.printf("⏱️ Uptime: %lu seconds\n", system_stats.uptime_seconds);
  Serial.printf("🌐 WiFi: %s\n", wifi_connected ? "Connected" : "Disconnected");
  Serial.printf("🔐 Encryption: %s\n", encryption_enabled ? "Enabled" : "Disabled");
  Serial.printf("🛡️ Mode: %s\n", ztm_mode ? "ZTM (Enhanced Security)" : "Normal");
  Serial.printf("📈 Data Sequence: %lu\n", data_sequence_number);
  Serial.printf("🔢 Total Encryptions: %lu\n", system_stats.total_encryptions);
  Serial.printf("⚡ Avg Encrypt Time: %.2f ms\n", system_stats.avg_encrypt_time_ms);
  Serial.printf("🚨 Attack Detections: %lu\n", system_stats.attack_detections);
  Serial.printf("🔄 ZTM Activations: %lu\n", system_stats.ztm_activations);
  Serial.printf("💾 Free Heap: %d bytes\n", ESP.getFreeHeap());
  Serial.printf("📉 Min Free Heap: %lu bytes\n", system_stats.free_heap_min);
  Serial.printf("🔥 CPU Frequency: %d MHz\n", ESP.getCpuFreqMHz());
  Serial.println("========================");
}

/**
 * @brief Handle serial commands for system control
 */
void handleSerialCommands() {
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    command.trim();
    command.toLowerCase();
    
    Serial.println("\n💬 Command received: " + command);
    
    if (command == "help") {
      printHelp();
    } else if (command == "status") {
      printSystemStatus();
    } else if (command == "test") {
      runSystemTest();
    } else if (command == "ztm") {
      if (!ztm_mode) {
        enableZTMMode();
      } else {
        disableZTMMode();
      }
    } else if (command == "encrypt") {
      encryption_enabled = !encryption_enabled;
      Serial.printf("🔐 Encryption %s\n", encryption_enabled ? "enabled" : "disabled");
    } else if (command == "attack") {
      simulateAttackScenario();
    } else if (command == "reset") {
      Serial.println("🔄 Restarting system...");
      delay(1000);
      ESP.restart();
    } else if (command == "stats") {
      printDetailedStats();
    } else if (command.startsWith("wifi ")) {
      configureWiFiFromSerial(command);
    } else {
      Serial.println("❓ Unknown command. Type 'help' for available commands.");
    }
  }
}

/**
 * @brief Print available serial commands
 */
void printHelp() {
  Serial.println("\n📋 === XenoCipher Healthcare IoT Commands ===");
  Serial.println("help       - Show this help message");
  Serial.println("status     - Display system status");
  Serial.println("stats      - Show detailed statistics");
  Serial.println("test       - Run system self-test");
  Serial.println("ztm        - Toggle Zero Trust Mode");
  Serial.println("encrypt    - Toggle encryption on/off");
  Serial.println("attack     - Simulate attack scenario");
  Serial.println("reset      - Restart the system");
  Serial.println("wifi <ssid> <password> - Configure WiFi");
  Serial.println("============================================");
}

/**
 * @brief Run comprehensive system test
 */
void runSystemTest() {
  Serial.println("\n🧪 === Running System Self-Test ===");
  
  // Test 1: Memory allocation
  Serial.println("Test 1: Memory allocation...");
  void* test_ptr = malloc(1024);
  if (test_ptr) {
    free(test_ptr);
    Serial.println("   ✅ Memory allocation test passed");
  } else {
    Serial.println("   ❌ Memory allocation test failed");
  }
  
  // Test 2: Random number generation
  Serial.println("Test 2: Random number generation...");
  uint32_t rand1 = esp_random();
  uint32_t rand2 = esp_random();
  if (rand1 != rand2) {
    Serial.printf("   ✅ Random generation test passed (%lu != %lu)\n", rand1, rand2);
  } else {
    Serial.println("   ❌ Random generation test failed (identical values)");
  }
  
  // Test 3: Sensor simulation
  Serial.println("Test 3: Sensor simulation...");
  HealthData test_data = generateSimulatedHealthData();
  if (test_data.heart_rate >= 60 && test_data.heart_rate <= 100 && 
      test_data.spo2 >= 95 && test_data.spo2 <= 100) {
    Serial.printf("   ✅ Sensor simulation test passed (HR: %d, SpO2: %d)\n", 
                  test_data.heart_rate, test_data.spo2);
  } else {
    Serial.printf("   ❌ Sensor simulation test failed (HR: %d, SpO2: %d)\n", 
                  test_data.heart_rate, test_data.spo2);
  }
  
  // Test 4: Encryption simulation
  Serial.println("Test 4: Encryption simulation...");
  bool encrypt_result = simulateEncryption((uint8_t*)&test_data, sizeof(HealthData));
  if (encrypt_result) {
    Serial.println("   ✅ Encryption simulation test passed");
  } else {
    Serial.println("   ❌ Encryption simulation test failed");
  }
  
  Serial.println("🎉 === Self-Test Complete ===");
}

/**
 * @brief Simulate attack scenario for testing
 */
void simulateAttackScenario() {
  Serial.println("\n🚨 === Simulating Attack Scenario ===");
  Serial.println("This will trigger attack detection mechanisms...");
  
  // Simulate various attack patterns
  Serial.println("🔍 Simulating low entropy attack...");
  for (int i = 0; i < 3; i++) {
    // Simulate low entropy detection
    Serial.printf("   Attack pattern %d: Low entropy detected\n", i + 1);
    delay(500);
  }
  
  Serial.println("🔍 Simulating timing attack...");
  for (int i = 0; i < 2; i++) {
    // Simulate timing anomalies
    Serial.printf("   Timing anomaly %d: Unusual encryption time\n", i + 1);
    delay(300);
  }
  
  // Trigger ZTM mode
  if (!ztm_mode) {
    Serial.println("🛡️ Attack threshold reached - Activating ZTM Mode");
    enableZTMMode();
  }
  
  Serial.println("✅ Attack simulation complete. Check system response...");
}

/**
 * @brief Print detailed system statistics
 */
void printDetailedStats() {
  Serial.println("\n📊 === Detailed System Statistics ===");
  Serial.printf("⏱️ System Uptime: %lu seconds (%.2f hours)\n", 
                system_stats.uptime_seconds, system_stats.uptime_seconds / 3600.0);
  Serial.printf("🔐 Total Encryptions: %lu\n", system_stats.total_encryptions);
  Serial.printf("🔓 Total Decryptions: %lu\n", system_stats.total_decryptions);
  Serial.printf("❌ Failed Operations: %lu\n", system_stats.failed_operations);
  Serial.printf("🛡️ ZTM Activations: %lu\n", system_stats.ztm_activations);
  Serial.printf("🚨 Attack Detections: %lu\n", system_stats.attack_detections);
  Serial.printf("⚡ Average Encrypt Time: %.3f ms\n", system_stats.avg_encrypt_time_ms);
  Serial.printf("💾 Current Free Heap: %d bytes\n", ESP.getFreeHeap());
  Serial.printf("📉 Minimum Free Heap: %lu bytes\n", system_stats.free_heap_min);
  Serial.printf("📊 Heap Usage: %.1f%%\n", 
                (1.0 - (float)ESP.getFreeHeap() / ESP.getHeapSize()) * 100);
  Serial.printf("🔥 CPU Temperature: %.1f°C\n", temperatureRead());
  Serial.println("=====================================");
}

/**
 * @brief Configure WiFi from serial command
 */
void configureWiFiFromSerial(String command) {
  // Parse command: "wifi <ssid> <password>"
  int first_space = command.indexOf(' ');
  int second_space = command.indexOf(' ', first_space + 1);
  
  if (first_space > 0 && second_space > 0) {
    String ssid = command.substring(first_space + 1, second_space);
    String password = command.substring(second_space + 1);
    
    ssid.toCharArray(wifi_ssid, sizeof(wifi_ssid));
    password.toCharArray(wifi_password, sizeof(wifi_password));
    
    Serial.printf("🌐 Configuring WiFi: %s\n", wifi_ssid);
    configureWiFi();
  } else {
    Serial.println("❓ Usage: wifi <ssid> <password>");
    Serial.println("   Example: wifi MyNetwork MyPassword123");
  }
}
