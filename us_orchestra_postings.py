import requests
from bs4 import BeautifulSoup
import hashlib
import os
import smtplib
import ssl
from email.message import EmailMessage
import time
from datetime import datetime
import re


# Email configuration
smtpserver = "smtp.gmail.com"
port = 465
senderemail = "zorerekin@gmail.com"
receiveremail = "zorerekin@gmail.com"
password = os.getenv("EMAIL_PASSWORD")

instruments = [
    "Violin", "Viola", "Cello", "Double Bass", "Flute", "Oboe", "Clarinet", "Bassoon",
    "Trumpet", "Trombone", "Horn", "Tuba", "Percussion", "Harp", "Piano", "Saxophone",
    "Guitar", "Bass", "Drums", "Keyboard", "Timpani", "Marimba", "Xylophone", "Organ"
]


# Regex to find phrases indicating deadlines and dates
deadline_phrase_pattern = re.compile(
    r"(Resume deadline\s*\w+\s\d{1,2},\s\d{4})"
    r"|(Resumes? due on or before:\s*\w+\s\d{1,2},\s\d{4})"
    r"|(Please apply no later than\s*\w+\s\d{1,2},\s\d{4})",
    re.IGNORECASE
)


# Send an email notification
def send_email(subject, body):
    em = EmailMessage()
    em['From'] = senderemail
    em['To'] = receiveremail
    em['Subject'] = subject
    em.set_content(body)

    context = ssl._create_unverified_context()

    with smtplib.SMTP_SSL(smtpserver, port, context=context) as server:
        server.login(senderemail, password)
        server.sendmail(senderemail, receiveremail, em.as_string())


# Get the hash of the webpage content and the content itself
def get_page_hash_and_content(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    content = soup.get_text()
    page_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
    return page_hash, soup


# Find current openings and their associated deadlines
def find_current_openings_and_deadlines(soup):
    openings_with_deadlines = []
    headers = soup.find_all(re.compile('^h[1-6]$'))
    
    for header in headers:
        text = header.get_text()
        if any(instrument.lower() in text.lower() for instrument in instruments):
            deadline = "Not specified"
            combined_text = header.get_text(separator=" ").strip() + " "
            container = header.find_parent('details') or header.find_parent('div')
            if container:
                # Traverse through all descendant elements to collect text
                for element in container.find_all(recursive=True):
                    combined_text += element.get_text(separator=" ").strip() + " "
            
            match = deadline_phrase_pattern.search(combined_text)
            print(header)
            # Search for the deadline in the concatenated text
            if match:
                deadline = match.group(0)
                print(f"Found deadline: {deadline} for {text.strip()}")
            
            openings_with_deadlines.append(f"{text.strip()} - Deadline: {deadline}")
    
    return openings_with_deadlines


# Check for changes on a webpage
def check_for_updates(url, hash_file):
    # Use /tmp directory for writing files in AWS Lambda
    hash_file_path = f"/tmp/{hash_file}"
     
    new_hash, soup = get_page_hash_and_content(url)
    change_detected = False
    new_openings = []
    all_openings = find_current_openings_and_deadlines(soup)

    # Check if hash file exists
    if os.path.exists(hash_file_path):
        with open(hash_file_path, 'r') as file:
            old_hash = file.read()

        if new_hash != old_hash:
            change_detected = True
            old_openings = set(file.read().splitlines())

            for opening in all_openings:
                if opening not in old_openings:
                    new_openings.append(opening)
    else:
        change_detected = True

    # Save the current hash to the file
    with open(hash_file_path, 'w') as file:
        file.write(new_hash)

    # Save the current openings to the file
    with open(f"{hash_file_path}_openings.txt", 'w') as file:
        file.write("\n".join(all_openings))

    return change_detected, all_openings, new_openings


# Monitor multiple webpages and send a summary email
def monitor_webpages(pages, interval=3600):
    summary = []
    changes_detected = False

    for page, hash_file in pages.items():
        change_detected, all_openings, new_openings = check_for_updates(page, hash_file)
        if change_detected:
            if all_openings:
                openings_list = []
                for opening in all_openings:
                    if opening in new_openings:
                        openings_list.append(f"**{opening}** (NEW!)")
                    else:
                        openings_list.append(opening)
                summary.append(f"Current openings on {page}:\n" + "\n".join(openings_list) + "\n")
            else:
                summary.append(f"No openings found on {page}.\n")
            changes_detected = True
        else:
            if all_openings:
                summary.append(f"Current openings on {page}:\n" + "\n".join(all_openings) + "\n")
            else:
                summary.append(f"No openings found on {page}.\n")

    if not changes_detected:
        summary.append("No changes detected on any of the monitored pages today!")

    summary_body = "\n".join(summary)

    current_date = datetime.now().strftime("%B %d, %Y")
    send_email(subject=f"US Orchestra Postings - {current_date}", body=summary_body)

    return summary_body 


# Lambda handler function
def lambda_handler(event, context):
    pages_to_monitor = {
        "https://www.bso.org/about/jobs/bso-auditions": "bso_auditions_hash.txt",
        "https://philorch.ensembleartsphilly.org/about-us/audition-for-the-philadelphia-orchestra": "philorch_auditions_hash.txt",
        "https://www.metopera.org/about/auditions/orchestra":  "metopera_auditions_hash.txt",
        "https://www.laphil.com/about/meet-the-orchestra/auditions": "laphil_auditions_hash.txt",
    }

    return monitor_webpages(pages_to_monitor)


if __name__ == "__main__":
    lambda_handler(None, None)