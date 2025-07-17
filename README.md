# ESP32-Attack-Defend-System

This code, written for an ESP32 microcontroller, implements a Wi-Fi MAC address collection and telemetry system with privacy-enhancing features, making it suitable for a cybersecurity project focused on network reconnaissance, privacy, or threat intelligence gathering.

Here's a breakdown of what the code does, suitable for a cybersecurity project explanation:

Project Goal/Purpose:

The primary goal of this project is to passively collect information about Wi-Fi devices in the vicinity by sniffing Wi-Fi management frames (specifically, probe requests and beacons) and extracting their MAC addresses and signal strengths (RSSI). This data is then periodically transmitted to a central collector for analysis. Crucially, the system incorporates features to enhance its stealth and privacy during operation.

Key Components and Their Cybersecurity Relevance:

Wi-Fi Promiscuous Mode (Sniffer)

esp_wifi_set_promiscuous(true); and esp_wifi_set_promiscuous_rx_cb(&snifferCallback);

Cybersecurity Relevance: This is the core of the reconnaissance capability. By enabling promiscuous mode, the ESP32 acts as a passive listener on the Wi-Fi airwaves, capturing all packets it "sees" regardless of whether they are addressed to it. This is fundamental for:

Network Mapping: Identifying active devices in a given physical area.

Intelligence Gathering: Understanding device density, movement patterns (if combined with location data), and potentially identifying unauthorized devices or rogue access points.

Traffic Analysis: While this code only extracts MACs, promiscuous mode is the first step for deeper packet inspection and analysis (e.g., identifying specific protocols, vulnerabilities).

MAC Address Collection and Tracking (seenMACs, recordMAC, isMACSeen)

The snifferCallback function extracts the source MAC address from management frames.

seenMACs and recordMAC store unique MAC addresses encountered.

Cybersecurity Relevance:

Device Inventory/Asset Discovery: Creating a list of all devices present in an environment. This is crucial for security audits and ensuring all devices are known and authorized.

Anomaly Detection: Identifying new or unexpected MAC addresses, which could indicate unauthorized devices, rogue clients, or even supply chain attacks (e.g., new, unapproved IoT devices).

Tracking and Profiling: Over time, collecting MAC addresses allows for basic tracking of device presence. With more advanced analysis, it could contribute to device profiling (e.g., "this MAC address is always seen around office hours").

De-authentication/Jamming Attacks: While not implemented here, knowing active MAC addresses is a prerequisite for launching de-authentication attacks against specific targets.

RSSI (Received Signal Strength Indicator) Collection (rssi, totalRSSI, avgRSSI)

The RSSI value from each captured packet is recorded.

Cybersecurity Relevance:

Proximity Analysis: Stronger RSSI indicates a device is closer. This can be used for rough localization or to identify devices that are physically very close to the sensor.

Signal Strength Anomalies: Sudden drops or spikes in RSSI could indicate interference, jamming attempts, or changes in device location.

Heatmapping: With multiple sensors, RSSI can be used to create heatmaps of device density or signal coverage, aiding in physical security assessments.

Privacy and Stealth Features (Obfuscation/Spoofing)

MAC Address Spoofing (spoofMAC, generateRandomMAC, esp_wifi_set_mac)

The ESP32's own MAC address is randomized on startup.

Cybersecurity Relevance: This is a key countermeasure against being easily identified or tracked. If the sensor's MAC address were static, an adversary observing Wi-Fi traffic could easily pinpoint the sensor's presence and activities. Spoofing helps the sensor blend in and avoid detection during reconnaissance. It demonstrates an understanding of operational security (OPSEC).

Hostname Spoofing (spoofHostname, WiFi.setHostname)

The device's hostname is randomized.

Cybersecurity Relevance: Similar to MAC spoofing, a unique or easily identifiable hostname could betray the device's purpose or presence on the network. Randomizing it further reduces its digital footprint and makes it harder to identify through network scans or DNS lookups.

XOR Encryption (xorEncrypt) and Base64 Encoding (base64::encode) for Telemetry

The collected telemetry data (JSON string) is first Base64 encoded and then XOR encrypted before transmission.

Cybersecurity Relevance:

Obfuscation/Evasion: This is a simple form of obfuscation to make the telemetry data less immediately readable if intercepted. It's not strong encryption, but it's enough to prevent casual inspection of the data stream. In a real-world scenario, this might evade very basic intrusion detection systems looking for plain-text data.

Data Integrity (Limited): While XOR isn't for integrity, the Base64 encoding ensures that the data is transmitted cleanly over protocols that might not handle raw binary well.

Demonstrates Awareness: The inclusion of these techniques shows an understanding that transmitted data should not be in the clear, even if the methods are basic for a high-security context.

Telemetry Transmission (UDP to Collector)

sendTelemetry() formats the collected data into a JSON string, then encodes/encrypts it, and sends it via UDP to a specified collectorIP and collectorPort.

delay(random(30000, 60000)); introduces a random delay for sending telemetry.

Cybersecurity Relevance:

Covert Channel/Exfiltration (Demonstration): This illustrates a basic method for exfiltrating collected data from a compromised or reconnaissance device. While simple UDP is easily detectable, it serves as a conceptual model. More advanced techniques might use ICMP tunneling, DNS tunneling, or encrypted HTTP/S.

Asynchronous Reporting: The random delay helps to make the communication pattern less predictable, potentially aiding in evasion of network monitoring systems that might flag regular, predictable outbound connections.

Centralized Analysis: The data is sent to a collector, implying a backend system for further analysis (e.g., a SIEM, a custom threat intelligence platform) where the collected MAC addresses and RSSI values can be correlated, visualized, and used for more sophisticated security insights.

Potential Project Enhancements/Future Work (Cybersecurity Focus):

Targeted Packet Types: Extend snifferCallback to parse and extract information from other packet types (e.g., probe requests to see what SSIDs devices are looking for, which can reveal user habits).

Stronger Encryption: Replace XOR with AES or TLS for secure communication with the collector, especially if sensitive data is being transmitted or the collector is external.

Authentication: Implement mutual authentication between the ESP32 and the collector to ensure data integrity and prevent unauthorized data injection.

Geospatial Mapping: Integrate GPS or other localization techniques to tag collected MAC addresses with physical locations, enabling more precise network mapping and tracking.

Machine Learning for Anomaly Detection: On the collector side, use ML to identify unusual MAC address patterns, new devices, or changes in signal strength that could indicate security incidents.

Firmware Over-the-Air (FOTA) Updates: Securely update the device's firmware remotely.

Power Optimization: For long-term deployment, optimize power consumption.

Legal and Ethical Considerations: Discuss the ethical implications of MAC address collection, privacy concerns, and compliance with regulations (e.g., GDPR) in a real-world scenario.

In summary, this ESP32 code is a practical demonstration of a Wi-Fi reconnaissance tool with built-in techniques to enhance its stealth and operational security. It's an excellent starting point for a cybersecurity project exploring topics like network monitoring, device enumeration, privacy implications of wireless technologies, and basic data exfiltration methods.
