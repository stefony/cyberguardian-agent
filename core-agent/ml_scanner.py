import sys
import json
import os
from pathlib import Path

def analyze_file(file_path):
    """
    Basic threat detection analysis
    Returns threat score 0-100
    """
    
    # Check if file exists
    if not os.path.exists(file_path):
        return {
            "error": "File not found",
            "threat_score": 0
        }
    
    # Get file info
    file_size = os.path.getsize(file_path)
    file_ext = Path(file_path).suffix.lower()
    
    # Basic threat scoring (dummy logic за сега)
    threat_score = 0
    threat_category = "safe"
    
    # Suspicious extensions
    dangerous_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js']
    if file_ext in dangerous_extensions:
        threat_score += 30
        threat_category = "suspicious"
    
    # Large files slightly suspicious
    if file_size > 10_000_000:  # 10MB
        threat_score += 10
    
    # Very small executables suspicious
    if file_ext in ['.exe', '.dll'] and file_size < 1000:
        threat_score += 40
        threat_category = "threat"
    
    return {
        "threat_score": min(threat_score, 100),
        "threat_category": threat_category,
        "file_size": file_size,
        "file_extension": file_ext,
        "analysis_version": "1.0-basic"
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided"}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = analyze_file(file_path)
    
    # Output JSON to stdout
    print(json.dumps(result))