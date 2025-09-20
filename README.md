#  Phishing Link Scanner – Brainwave Matrix Intern Project

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

#  Overview
This project is a Phishing Link Scanner built as part of my Brainwave Matrix Internship.  
It analyzes URLs using heuristics (rules of thumb) to detect suspicious patterns such as misleading domains, excessive dots, and keywords like "login" or "verify".  

The tool can:
- Scan **single URLs**  
- Process **batch URLs from CSV**  
- Export results into a **report.csv**  
- Optionally perform **live checks** (follow redirects, grab page title)  

---

##  Features
-  Heuristic-based phishing detection  
-  Batch scanning with CSV input  
-  Auto-generated CSV reports  
-  Lightweight and beginner-friendly  
-  Extensible for future improvements  

---

# Setup

Clone this repository and install dependencies:

```bash
git clone https://github.com/CyberRay007/Brainwave_Matrix_Intern.git
cd Brainwave_Matrix_Intern
pip install -r requirements.txt
Requirements (requirements.txt):

text
Copy code
requests
beautifulsoup4
pandas
 Usage
 Scan a single URL
bash
Copy code
python phishing_scanner.py --url "http://example.com/login"
 Scan a batch of URLs (CSV input)
bash
Copy code
python phishing_scanner.py --input_csv samples_urls.csv --output_csv report.csv
<details> <summary>📂 Sample Input CSV (click to expand)</summary>
csv
Copy code
url
https://www.microsoft.com
http://198.51.100.4/login
https://secure-paypa1.com/verify
http://example.com/update/account?user=you
https://bit.ly/3AbCdE
https://xn--pple-43d.com/login
https://accounts.google.com
http://sub1.sub2.sub3.sub4.domain.top/reset
https://mybank-secure-login.xyz/confirm
http://example.com/93485734987534987534
https://www.google.com/search?q=cybersecurity
https://github.com/CyberRay007/Brainwave_Matrix_Intern
https://www.microsoft.com/en-us
https://www.apple.com
https://www.amazon.com/gp/bestsellers
https://www.linkedin.com/in/yourprofile
https://www.facebook.com
https://twitter.com/home
https://www.instagram.com
https://www.paypal.com/myaccount/summary
https://stackoverflow.com/questions
https://en.wikipedia.org/wiki/Cybersecurity
https://pypi.org/project/requests/
https://pandas.pydata.org/
https://www.reddit.com/r/netsec/
https://www.netflix.com/browse
https://www.dropbox.com/login
https://slack.com/signin
https://zoom.us/join
https://aws.amazon.com/console
https://drive.google.com
https://mail.google.com
https://www.imdb.com
https://www.cnn.com
https://www.bbc.com/news
http://secure-paypal.example/login
https://paypal.verify.test/account
http://login-apple.example/signin,
https://appleid.verify.invalid/auth
http://account-google.example/update
https://google-secure.test/confirm
http://bank-secure.invalid/verify
https://chase-login.example/auth
http://wellsfargo.verify.test/session
https://netflix-activate.example/redeem
http://microsoft-office.verify.test/login
https://update-password.example/reset
http://verify-account.test/confirm
https://billing-paypal.invalid/invoice
http://paypa1-login.example/signin
https://rnicrosoft-login.test/security
http://secure-bank-example.test/portal
https://auth-verify.example/session
http://secure-login-bank.invalid/confirm
https://accounts-google.verify.test/login
http://bitly-like.test/abc123
https://tinyurl-mock.example/redirect
http://xn--pple-example.test/login
https://secure-paypal-verify.example/reset
http://login-security-example.invalid/confirm

</details>

Example generated CSV report:

📂 Project Structure
bash
Copy code
Brainwave_Matrix_Intern/
│── phishing_scanner.py   # Main scanner code
│── requirements.txt      # Dependencies
│── sample_urls.csv       # Example input
│── README.md             # Documentation
│── LICENSE               # MIT License
│── .gitignore            # Ignored files (e.g., report.csv, .venv/)
│── screenshots/          # Demo images

 License
This project is licensed under the MIT License – see the LICENSE file for details.

 Author
CyberRay007 – Cybersecurity Analyst & Ethical Hacker Intern @ Brainwave Matrix
