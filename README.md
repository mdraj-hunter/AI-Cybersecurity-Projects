# AI-Cybersecurity-Projects
A comprehensive collection of four modular security tools leveraging Artificial Intelligence and Machine Learning to detect, analyze, and mitigate digital threats. This project demonstrates the integration of data science with core cybersecurity principles.
📂 Project OverviewProjectFocus AreaTechnologyStatus01 Phishing DetectorNLP / URL AnalysisScikit-Learn, Flask✅ Complete02 Network IDSAnomaly DetectionScapy, Pandas✅ Complete03 Web ScannerVulnerability ResearchBeautifulSoup, Requests✅ Complete04 Malware DetectionStatic AnalysisPEfile, TensorFlow/CNN✅ Complete
🚀 Key Features
🎣 01. Phishing Detector
Analyzes URLs and email content to identify social engineering attempts.

Uses a Random Forest Classifier trained on 10,000+ malicious/benign links.

Extracts features like URL length, special character frequency, and domain age.

🕵️ 02. Network Intrusion Detection System (NIDS)
Monitors live network traffic to identify suspicious patterns such as Port Scanning or DDoS attacks.

Real-time packet sniffing using Scapy.

ML-based anomaly detection to flag traffic that deviates from a normal baseline.

🔍 03. Web Vulnerability Scanner
Automates the discovery of common web flaws.

Scans for XSS (Cross-Site Scripting) and SQL Injection entry points.

Generates a detailed security report in JSON/PDF format.

🦠 04. Malware Detection with ML
Classifies files as malicious or benign without execution.

Extracts features from PE (Portable Executable) headers.

Converts binary data into grayscale images for classification using a Convolutional Neural Network (CNN).

🛠️ Installation & Setup
Clone the repository:

Bash
git clone https://github.com/mdraj-hunter/AI-Cybersecurity-projects.git
cd CybersecurityAI-Projects
Set up a Virtual Environment:

Bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install Dependencies:

Bash
pip install -r requirements.txt
⚠️ Disclaimer
These tools are created for educational purposes only. Never use the Web Scanner or NIDS on networks or systems you do not own or have explicit permission to test. The author is not responsible for any misuse of this software.

✨ Author
mdraj-hunter * Cybersecurity & AI Enthusiast
