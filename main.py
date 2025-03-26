import re
import spacy
import pdfplumber
import fitz  # PyMuPDF
import requests
import asyncio
import aiohttp
from sentence_transformers import SentenceTransformer, util
import json
import os
from fuzzywuzzy import process
from collections import defaultdict
import time
import iocextract
import urllib.parse
import dns.resolver
from transformers import pipeline
from hashid import HashID
# For OCR from images
from PIL import Image
import pytesseract


# ----------------------------
# 1. Load Models and Data
# ----------------------------

# Ensure spaCy loads on GPU if available
try:
    spacy.require_gpu()  # Use this instead of prefer_gpu()
    print("[✅] Using GPU for spaCy")
except:
    print("[⚠️] No GPU found, running on CPU")

# Load Models
nlp = spacy.load("en_core_web_sm")  
sbert_model = SentenceTransformer("all-MiniLM-L6-v2")
targeted_entity_model = pipeline("ner", model="dslim/bert-base-NER")


# Load MITRE ATT&CK TTPs dynamically
def load_mitre_attack_ttp():
    MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        response = requests.get(MITRE_ATTACK_URL, timeout=10)
        response.raise_for_status()
        data = response.json()

        tactics, techniques, procedures = {}, {}, {}

        for obj in data["objects"]:
            if obj.get("type") == "x-mitre-tactic":  # Extract Tactics
                tactics[obj["external_references"][0]["external_id"]] = obj["name"]

            elif obj.get("type") == "attack-pattern":  # Extract Techniques
                techniques[obj["external_references"][0]["external_id"]] = obj["name"]

                # Extract Procedures (Real-world examples)
                description = obj.get("description", "")
                if "example" in description.lower():
                    procedures[obj["external_references"][0]["external_id"]] = description

        return tactics, techniques, procedures

    except requests.RequestException as e:
        print(f"[⚠️] Error loading MITRE ATT&CK data: {e}")
        return {}, {}, {}

# Load MITRE ATT&CK data for TTPS
MITRE_ATTACK_TACTICS, MITRE_ATTACK_TECHNIQUES, MITRE_ATTACK_PROCEDURES = load_mitre_attack_ttp()

# ----------------------------
# 2. PDF Text Extraction & Analysis
# ----------------------------

# Extract text from PDF using pdfplumber
def extract_text_from_pdf(pdf_path):
    with pdfplumber.open(pdf_path) as pdf:
        # Join text from each page that has text
        text = "\n".join(page.extract_text() for page in pdf.pages if page.extract_text())
    return text

# ----------------------------
# 3. Image Extraction and OCR
# ----------------------------

# Extract images from PDF using PyMuPDF (fitz)
def extract_images_from_pdf(pdf_path, output_folder="extracted_images"):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    doc = fitz.open(pdf_path)
    extracted_files = []

    for page_number in range(len(doc)):
        page = doc[page_number]
        image_list = page.get_images(full=True)

        for image_index, img in enumerate(image_list, start=1):
            xref = img[0]
            base_image = doc.extract_image(xref)
            image_bytes = base_image["image"]
            image_ext = base_image["ext"]

            image_filename = os.path.join(
                output_folder,
                f"page_{page_number + 1}_img_{image_index}.{image_ext}"
            )

            with open(image_filename, "wb") as f:
                f.write(image_bytes)

            extracted_files.append(image_filename)

    return extracted_files

# Use Tesseract OCR to extract text from an image file
def extract_text_from_image(image_path):
    try:
        image = Image.open(image_path)
        # You can pass additional configuration to pytesseract if needed
        text = pytesseract.image_to_string(image)
        print(f"Text Extracted successfully")
        return text
    except Exception as e:
        print(f"[⚠️] Error processing image {image_path}: {e}")
        return ""

# Extract text from a list of images
def extract_text_from_images(image_files):
    combined_text = ""
    for image_path in image_files:
        text = extract_text_from_image(image_path)
        combined_text += "\n" + text
    return combined_text

# ----------------------------
# 4. Threat Intelligence Analysis Functions
# ----------------------------


#DOMAIN
def get_tld_regex():
    tld_url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    response = requests.get(tld_url)

    if response.status_code == 200:
        tlds = response.text.splitlines()
        tlds = [tld.lower() for tld in tlds if not tld.startswith("#")]
        return rf"\b(?:[a-zA-Z0-9-]+\.)+(?:{'|'.join(tlds)})\b"
    else:
        return r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|gov|edu|mil|co|kr|io|cn|jp|ru|info|biz|tv|in|uk|us)\b"

DOMAIN_PATTERN = get_tld_regex()

#EMAIL

EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

def extract_raw_emails(text):
    """
    Extracts strictly formatted email addresses using regex.
    """
    return set(re.findall(EMAIL_PATTERN, text))

def validate_email_domain(email):
    """
    Validates if an email domain has valid MX (Mail Exchange) records.
    """
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')  # Check if domain has mail servers
        return bool(mx_records)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        return False  # Domain is invalid

def extract_valid_emails(text):
    """
    Extracts emails and validates them using MX/SPF records.
    """
    extracted_emails = extract_raw_emails(text)
    return [email for email in extracted_emails if validate_email_domain(email)]



#HASHES
HASH_PATTERNS = [
    r"\b[a-fA-F0-9]{32}\b",  # MD5 or IMPHASH
    r"\b[a-fA-F0-9]{40}\b",  # SHA1, PEHASH
    r"\b[a-fA-F0-9]{64}\b",  # SHA256 or AUTHENTIHASH
    r"\b[a-fA-F0-9]{128}\b",  # SHA512
    r"T[a-fA-F0-9]{69,71}",  # TLSH (Trend Micro Locality-Sensitive Hashing)
    r"\b[0-9]{1,5}:[A-Za-z0-9+/]{20,200}:[A-Za-z0-9+/]{20,200}\b"  # SSDEEP (Fuzzy Hashing)
]

hashid = HashID()

def extract_hash_candidates(text):
    hash_candidates = set()
    for pattern in HASH_PATTERNS:
        hash_candidates.update(re.findall(pattern, text))
        print (hash_candidates)
    return list(hash_candidates)

def classify_hash(hash_value):
    """
    Identifies the hash type using hashid, then applies length-based refinement.
    """
    results = list(hashid.identifyHash(hash_value))  # Convert generator to list
    hashid_guess = results[0].name if results else "Unknown"

    return refine_hash_classification(hash_value, hashid_guess)

def refine_hash_classification(hash_value, hashid_guess):
    """
    Improves accuracy of hash classification using length, known hash structures,
    and manual refinement after HashID’s initial guess.
    """
    hash_length = len(hash_value)

    # 🔹 Handle Exact-Length Hashes First
    if hash_length == 32:
        if hashid_guess in ["MD2", "MD4", "MD5"]:
            return "MD5"  # MD5 is most common
        return "IMPHASH"  # PE Import Hash (IMPHASH)

    elif hash_length == 40:
        return "PEHASH" if hashid_guess == "SHA1" else "SHA1"

    elif hash_length == 64:
        return "Authentihash" if hashid_guess in ["SHA256", "Authentihash"] else "SHA256"

    elif hash_length == 128:
        return "SHA512"

    # 🔹 Handle Structure-Based Hashes
    if hash_length == 72 and hash_value.startswith("T"):
        return "TLSH"  # Trend Micro Locality-Sensitive Hashing

    if ":" in hash_value and len(hash_value.split(":")) == 3:
        return "SSDEEP"  # Fuzzy Hashing

    if hash_value.startswith("$2a$") or hash_value.startswith("$2b$"):
        return "BCRYPT"  # Bcrypt Password Hashing

    return hashid_guess  # Return refined guess

def extract_hashes(text):
    hash_candidates = extract_hash_candidates(text)
    classified_hashes = {h: classify_hash(h) for h in hash_candidates}
    print(classified_hashes)
    return classified_hashes

#URLS
def check_virustotal(url):
    time.sleep(16)  # Prevents rate-limiting (4 requests/min for free API)
    headers = {"x-apikey": api_keys["virustotal"]}
    encoded_url = urllib.parse.quote(url, safe="")
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0
    return False

#IOCs
def extract_iocs(text):
    #IP ADDRESSES
    ipv4_pattern = r'\b(?:[0-9]{1,3}|xx)\.(?:[0-9]{1,3}|xx)\.(?:[0-9]{1,3}|xx)\.(?:[0-9]{1,3}|xx)\b'

    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}|xx)(?::(?:[0-9a-fA-F]{1,4}|xx)){7}\b' \
               r'|\b(?:[0-9a-fA-F]{1,4}|xx)(?::(?:[0-9a-fA-F]{1,4}|xx)){0,6}::(?:[0-9a-fA-F]{1,4}|xx){0,1}\b' \
               r'|\bfe80:(?::(?:[0-9a-fA-F]{0,4}|xx)){0,4}%[0-9a-zA-Z]{1,}\b' \
               r'|\b::(ffff(:0{1,4}){0,1}:){0,1}(?:[0-9]{1,3}|xx)(?:\.(?:[0-9]{1,3}|xx)){3}\b'


    #URLS
    extracted_urls = iocextract.extract_urls(text)
    #Filter URLs: Only include URLs with HTTP/S and potential malware indicators
    filtered_urls = [url for url in extracted_urls if "http" in url.lower() or "exe" in url or "download" in url]
    return {
        "IPv4 Addresses": list(set(re.findall(ipv4_pattern, text))),
        "IPv6 Addresses": list(set(re.findall(ipv6_pattern, text))),
        "Domains": list(set(re.findall(DOMAIN_PATTERN, text))),
        "URLs": filtered_urls,
        "Hashes": list(extract_hashes(text)),
        "Email Addresses": extract_valid_emails(text)
    }


#THREAT ACTORS
def fetch_known_threat_actors():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url)
    threat_actors = set()
    if response.status_code == 200:
        data = response.json()
        for obj in data["objects"]:
            if obj.get("type") == "intrusion-set":  # Intrusion sets = threat actor groups
                threat_actors.add(obj.get("name"))
    return threat_actors

KNOWN_THREAT_ACTORS = fetch_known_threat_actors()


#TARGETED ENTITIES
# Attack & Culprit Keywords
ATTACK_KEYWORDS = {
    "targeted", "compromised", "attacked", "breached", "hacked",
    "data leak", "ransomware attack", "victim", "cyberattack",
    "penetration", "infiltrated", "exploited", "impacted", "disrupted",
    "taken offline", "infected", "data theft", "data breach", "exposed",
    "accessed without authorization", "service disruption", "DDoS attack",
    "shutdown", "defaced", "unauthorized access", "stolen credentials",
    "zero-day vulnerability", "session hijacking", "watering hole attack",
    "man-in-the-middle attack", "APT attack", "espionage", "data exfiltration"
}

def extract_targeted_entities_local(text, threat_actors):
    ner_results = targeted_entity_model(text)


    full_entities = []  # Reconstruct full entity names
    current_entity = ""

    for entity in ner_results:
        word = entity["word"]

        if entity["entity"].startswith("B-"):  # Start of a new entity
            if current_entity:
                full_entities.append(current_entity.strip())
            current_entity = word  # Start new entity

        elif entity["entity"].startswith("I-"):  # Continuation of previous entity
            if word.startswith("##"):
                current_entity += word[2:]  # Remove '##' from subword
            else:
                current_entity += " " + word
        else:
            if current_entity:
                full_entities.append(current_entity.strip())
            current_entity = ""  # Reset entity tracker

    if current_entity:
        full_entities.append(current_entity.strip())  # Add last entity


    targeted_entities = set()
    text_sentences = text.split(". ")  # Split for better context

    #Improved Context Matching
    for entity in full_entities:
        if entity in threat_actors:
            continue  
        for i, sentence in enumerate(text_sentences):
            if entity.lower() in sentence.lower():

                # Look at surrounding sentences for attack keywords
                nearby_text = " ".join(text_sentences[max(0, i-1): min(len(text_sentences), i+2)])

                sentence_embedding = sbert_model.encode(nearby_text, convert_to_tensor=True)

                for keyword in ATTACK_KEYWORDS:
                    keyword_embedding = sbert_model.encode(keyword, convert_to_tensor=True)
                    similarity = util.pytorch_cos_sim(sentence_embedding, keyword_embedding)

                    if similarity.item() > 0.35:  # Lowered threshold for better matching
                        targeted_entities.add(entity)

    return list(targeted_entities)

#NAMED ENTITIES - THREAT ACTORS, TARGETED ENTITIES
def extract_named_entities(text):
    doc = nlp(text)
    threat_actors  = set()
    # targeted_entities = defaultdict(set)

    for ent in doc.ents:
        entity_text = ent.text.strip()

        best_match, score = process.extractOne(entity_text, KNOWN_THREAT_ACTORS)
        if score > 80:  # Adjust threshold based on accuracy needs
            threat_actors.add(best_match)

    # Extract targeted entities using enhanced method
    targeted_entities = extract_targeted_entities_local(text, threat_actors)

    return {
        "Threat Actors": list(threat_actors),
        "Targeted Entities": targeted_entities
    }


#TTPS
def extract_ttps(text):
    extracted_tactics, extracted_techniques, extracted_procedures = set(), set(), {}

    #Step 1: Extract Tactics (Regex Matching)
    tactic_patterns = {
    r"Reconnaissance": "TA0043",
    r"Resource Development": "TA0042",
    r"Initial Access": "TA0001",
    r"Execution": "TA0002",
    r"Persistence": "TA0003",
    r"Privilege Escalation": "TA0004",
    r"Defense Evasion": "TA0005",
    r"Credential Access": "TA0006",
    r"Discovery": "TA0007",
    r"Lateral Movement": "TA0008",
    r"Collection": "TA0009",
    r"Exfiltration": "TA0010",
    r"Command and Control": "TA0011",
    r"Impact": "TA0040",
    }

    for tactic, code in tactic_patterns.items():
        if re.search(tactic, text, re.IGNORECASE):
            extracted_tactics.add((code, tactic))

    #Step 2: Extract Techniques (Semantic Similarity)
    text_embedding = sbert_model.encode(text.lower(), convert_to_tensor=True)

    for technique_id, technique_name in MITRE_ATTACK_TECHNIQUES.items():
        # 🔹 Regex Matching (High Confidence)
        if re.search(re.escape(technique_name), text, re.IGNORECASE):
            extracted_techniques.add((technique_id, technique_name))
            continue

        # 🔹 Semantic Similarity (Fallback)
        technique_embedding = sbert_model.encode(technique_name.lower().strip(), convert_to_tensor=True)
        similarity = util.pytorch_cos_sim(text_embedding, technique_embedding)

        if similarity.item() > 0.4:  # Lower threshold to capture more matches
            extracted_techniques.add((technique_id, technique_name))

    #Step 3: Extract Procedures
    for technique_id, technique_name in extracted_techniques:
        if technique_id in MITRE_ATTACK_PROCEDURES:
            extracted_procedures[technique_id] = MITRE_ATTACK_PROCEDURES[technique_id]

    return {
        "Tactics": list(extracted_tactics),
        "Techniques": list(extracted_techniques),
        "Procedures": extracted_procedures
    }

# MALWARE
def query_virustotal(hash_value, api_key):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": api_key.strip()}
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal API Error: {e}"}

def query_hybrid_analysis(hash_value, api_key):
    try:
        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {"api-key": api_key.strip()}
        data = {"hash": hash_value}
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Hybrid Analysis API Error: {e}"}

def query_malwarebazaar(hash_value):
    try:
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_info", "hash": hash_value}
        response = requests.post(url, data=data)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"MalwareBazaar API Error: {e}"}


def fetch_malware_details(hash_value, api_keys):
    vt_result = query_virustotal(hash_value, api_keys["virustotal"])
    ha_result = query_hybrid_analysis(hash_value, api_keys["hybrid_analysis"])
    mb_result = query_malwarebazaar(hash_value)

    return {
        "Hash": hash_value,
        "Hashes": {
            "md5": vt_result.get("data", {}).get("attributes", {}).get("md5", "N/A"),
            "sha1": vt_result.get("data", {}).get("attributes", {}).get("sha1", "N/A"),
            "sha256": vt_result.get("data", {}).get("attributes", {}).get("sha256", "N/A"),
            "ssdeep": vt_result.get("data", {}).get("attributes", {}).get("ssdeep", "N/A"),
            "TLSH": vt_result.get("data", {}).get("attributes", {}).get("tlsh", "N/A")
        },

        "VirusTotal": { "Classification": vt_result.get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown"),
            "size": vt_result.get("data", {}).get("attributes", {}).get("size", "Unknown"),
            "magic": vt_result.get("data", {}).get("attributes", {}).get("magic", "Unknown"),
            "trid": vt_result.get("data", {}).get("attributes", {}).get("trid", "Unknown"),
            "Type": vt_result.get("data", {}).get("type", "Unknown"),
            "Type_Tags": vt_result.get("data", {}).get("attributes", {}).get("type_tags", []),
            "Type_extension": vt_result.get("data", {}).get("attributes", {}).get("type_extension", "Unknown"),
            "last_submission_date": vt_result.get("data", {}).get("attributes", {}).get("last_submission_date", "Unknown"),
            "Last_Analysis_Stats": vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            "last modification date": vt_result.get("data", {}).get("attributes", {}).get("last_modification_date", "Unknown"),
            "type_description": vt_result.get("data", {}).get("attributes", {}).get("type_description", "Unknown"),
            "first_seen_itw_date": vt_result.get("data", {}).get("attributes", {}).get("first_seen_itw_date", "Unknown"),
            # pe-info"
            "time_stamp": vt_result.get("data", {}).get("attributes", {}).get("pe_info", {}).get("time_stamp","Unknown"),
            "imphash": vt_result.get("data", {}).get("attributes", {}).get("pe_info", {}).get("imphash", []),
            "machine_type": vt_result.get("data", {}).get("attributes", {}).get("pe_info", {}).get("machine_type", "Unknown"),
            "entry_point": vt_result.get("data", {}).get("attributes", {}).get("pe_info", {}).get("entry_point", "Unknown"),
            "resources_langs": vt_result.get("data", {}).get("attributes", {}).get("pe_info", {}).get("resources_langs", []),
            "resources_type": vt_result.get("data", {}).get("attributes", {}).get("pe_info", {}).get("resources_type", []),
        },

        "Hybrid Analysis": {
            "Verdict": ha_result[0].get("verdict", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "Classification_tags": ha_result[0].get("classification_tags", []) if isinstance(ha_result, list) and ha_result else [],
            "Tags": ha_result[0].get("tags", []) if isinstance(ha_result, list) and ha_result else [],
            "job_id": ha_result[0].get("job_id", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "environmental_tags": ha_result[0].get("enviromental_tags", []) if isinstance(ha_result, list) and ha_result else [],
            "environmental_description": ha_result[0].get("environmental_description", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "size": ha_result[0].get("size", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "Type": ha_result[0].get("type", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "type-short": ha_result[0].get("type_short", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "state": ha_result[0].get("state", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "vx_family": ha_result[0].get("vx_family", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "analysis_start_date": ha_result[0].get("analysis_start_date", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "Threat_level": ha_result[0].get("threat_level", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "verdict": ha_result[0].get("verdict", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "Threat_score": ha_result[0].get("threat_score", "N/A") if isinstance(ha_result, list) and ha_result else "N/A",
            "veredict" : ha_result[0].get("veredict", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
            "network_mode": ha_result[0].get("network_mode", "Unknown") if isinstance(ha_result, list) and ha_result else "Unknown",
        } if ha_result !=[]  else {"message":"Hybride Analysis:NO data found"},

        "MalwareBazaar": {
            "File Name": mb_result.get("data", [{}])[0].get("file_name", "Unknown"),
            "file_size": mb_result.get("data", [{}])[0].get("file_size", "Unknown"),
            "first-seen": mb_result.get("data", [{}])[0].get("first_seen", "Unknown"),
            "last-seen": mb_result.get("data", [{}])[0].get("last_seen", "Unknown"),
            "Reporter": mb_result.get("data", [{}])[0].get("reporter", "Unknown"),
            "file_type_mime": mb_result.get("data", [{}])[0].get("file_type_mime", "Unknown"),
            "file_type": mb_result.get("data", [{}])[0].get("file_type", "Unknown"),
            "reporter": mb_result.get("data", [{}])[0].get("reporter", "Unknown"),
            "signature": mb_result.get("data", [{}])[0].get("signature", "Unknown"),
            "imphash": mb_result.get("data", [{}])[0].get("imphash", "Unknown"),
            "tlsh": mb_result.get("data", [{}])[0].get("tlsh", "Unknown"),
            "tags": mb_result.get("data", [{}])[0].get("tags", "Unknown"),
            "intelligence": mb_result.get("data", [{}])[0].get("intelligence", "Unknown"),
        }if mb_result.get("query_status")=="ok" else {"message": "MalwareBazaar: No data found"}
    }


# Function to extract malware details from VirusTotal using hash values
def get_virus_total_details(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": api_keys["virustotal"]
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            data = json_response.get('data', {})
            malware_details = {
                'md5': data.get('id'),
                'sha1': data.get('attributes', {}).get('sha1'),
                'sha256': data.get('attributes', {}).get('sha256'),
                'ssdeep': data.get('attributes', {}).get('ssdeep', 'N/A'),
                'TLSH': data.get('attributes', {}).get('tlsh', 'N/A'),
                'tags': ', '.join(data.get('attributes', {}).get('tags', []))
            }
            return malware_details
    except Exception as e:
        print(f"Error: {e}")
        return None

# ----------------------------
# 5. Combined Threat Intelligence Extraction
# ----------------------------

async def extract_threat_intelligence(pdf_path, api_key):
    # Extract text from PDF
    pdf_text = extract_text_from_pdf(pdf_path)

    # Extract images from PDF and then extract text from these images via OCR
    image_files = extract_images_from_pdf(pdf_path)
    image_text = extract_text_from_images(image_files)

    # Combine text from PDF and images
    combined_text = pdf_text + "\n" + image_text

    # Run extraction functions on the combined text
    iocs = extract_iocs(combined_text)
    named_entities = extract_named_entities(combined_text)
    ttps = extract_ttps(combined_text)

    # Extracting Malware Information
    malware_info = {
        hash_value: fetch_malware_details(hash_value, api_keys)
        for hash_value in iocs["Hashes"]
    }

    return {
        "IoCs": iocs,
        "TTPs": ttps,
        **named_entities,
        "Malware": malware_info
    }

# ----------------------------
# 6. Main Execution
# ----------------------------

if __name__ == "__main__":

    api_keys = {
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "hybrid_analysis": "YOUR_HYBRID_ANALYSIS_API_KEY"
    }

    # Ensure API keys are properly formatted
    api_keys["virustotal"] = api_keys["virustotal"].strip()
    api_keys["hybrid_analysis"] = api_keys["hybrid_analysis"].strip()

    pdf_path = "report.pdf"  # Replace with your PDF file path

    # Run threat intelligence extraction
    async def main():
        extracted_data = await extract_threat_intelligence(pdf_path, api_keys)
        print("=== Threat Intelligence Data ===")
        print(json.dumps(extracted_data, indent=4))

    asyncio.run(main()) 