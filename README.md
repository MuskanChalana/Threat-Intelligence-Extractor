# Threat Intelligence Extraction

## Overview
This project extracts threat intelligence from cybersecurity reports, identifying **Indicators of Compromise (IoCs)**, **Tactics, Techniques, and Procedures (TTPs)**, **Threat Actors**, **Malware**, and **Targeted Entities**. It leverages NLP models and external threat intelligence sources to enhance entity recognition and filtering.

## Features
- **Extract IoCs**: Detects IPs, domains, hashes, and URLs using `iocextract` and external validation.
- **Identify TTPs**: Matches attack patterns with **MITRE ATT&CK** framework.
- **Threat Actor Recognition**: Cross-references known actors from **MITRE ATT&CK**.
- **Targeted Entities Extraction**: Identifies organizations and victims from cybersecurity reports.
- **Malware Detection**: Extracts malware names and enhances metadata with **VirusTotal**, **Hybrid Analysis**, and **MalwareBazaar**.
- **Contextual NLP Processing**: Uses **spaCy (en_core_web_sm)**, **BERT-based NER (`dslim/bert-base-NER`)**, and **SBERT (`all-MiniLM-L6-v2`)** for entity recognition and filtering.
- **OCR Support**: Extracts intelligence from image-based PDFs using **Tesseract OCR**.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/threat-intelligence-extractor.git
cd threat-intelligence-extractor

# Install dependencies
pip install -r requirements.txt

# Download necessary NLP models
python -m spacy download en_core_web_sm
```

## Configuration
Set up API keys in a `.env` file:

```yaml
VIRUSTOTAL_API_KEY=your_virustotal_api_key
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key
```

## Usage
Run the script on a cybersecurity report:

```bash
python extract_threat_intelligence.py --pdf report.pdf
```

### Example Output
```json
{
  "IoCs": {
    "IPv4 Addresses": ["192.168.1.1", "8.8.8.8"],
    "IPv6 Addresses": ["2001:db8::ff00:42:8329"],
    "Domains": ["malicious.com", "phishing-site.net"],
    "URLs": ["http://malicious.com/bad.exe", "https://attack.com/payload"],
    "Hashes": ["d41d8cd98f00b204e9800998ecf8427e", "e99a18c428cb38d5f260853678922e03"],
    "Email Addresses": ["attacker@malicious.com", "phisher@spoofed.net"]
  },
  "TTPs": {
    "Tactics": ["TA0001 - Initial Access"],
    "Techniques": ["T1071 - Application Layer Protocol"],
    "Procedures": ["Spear-phishing attachment used to deliver malware."]
  },
  "Threat Actors": ["Lazarus Group"],
  "Malware": {
    "TrickBot": {
      "VirusTotal": {"Classification": "Trojan"},
      "Hybrid Analysis": {"Verdict": "Malicious"},
      "MalwareBazaar": {"Tags": ["banking trojan"]}
    },
    "Emotet": {
      "VirusTotal": {"Classification": "Worm"},
      "Hybrid Analysis": {"Verdict": "Suspicious"},
      "MalwareBazaar": {"Tags": ["malspam"]}
    }
  },
  "Targeted Entities": ["Company X", "Government Agency Y"]
}
```

## References
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [VirusTotal API](https://www.virustotal.com/gui/home/upload)
- [Hybrid Analysis API](https://www.hybrid-analysis.com/)
- [MalwareBazaar API](https://bazaar.abuse.ch/)
- MITRE ATT&CK Data: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- IANA TLDs List: `https://data.iana.org/TLD/tlds-alpha-by-domain.txt`
