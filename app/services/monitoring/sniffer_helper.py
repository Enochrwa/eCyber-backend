def _packet_handler(self, packet: Packet):
    """Enhanced packet processing with feature extraction"""
    self.start_time = time.perf_counter()

    with self.packet_counter.get_lock():
        self.packet_counter.value += 1

    try:
        # Process with enhanced feature extraction
        result = self.packet_processor.process_packet(packet)

        if result:
            features = result.get("features", {})
            threats = result.get("threats", [])
            ml_prediction = result.get("ml_prediction")

            # Log threats
            for threat in threats:
                self.sio_queue.put(("threat_detected", threat))

            # Send features for real-time analysis
            if features:
                self.sio_queue.put(
                    (
                        "packet_features",
                        {
                            "features": features,
                            "prediction": ml_prediction,
                            "timestamp": time.time(),
                        },
                    )
                )

    except Exception as e:
        logger.error(f"Enhanced packet processing error: {e}")
    finally:
        logger.debug(
            "Packet processing completed in %.4f seconds",
            time.perf_counter() - self.start_time,
        )


# Initialize the enhanced processor
self.packet_processor = EnhancedPacketProcessor()

# Load your trained model
self.packet_processor.load_model("path/to/your/cicids_model.pkl")

# Export features for training/validation
self.packet_processor.feature_extractor.export_features_csv("extracted_features.csv")

# Get system status
status = self.packet_processor.get_system_status()

processor = EnhancedPacketProcessor()

# For each packet captured:
result = processor.process_packet(packet)
print(result["threats"])  # List of detected threats
print(result["features"])  # Extracted features

# Get system status:
status = processor.get_system_status()
