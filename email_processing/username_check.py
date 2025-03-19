import re

# Liste over generiske termer
GENERIC_TERMS = [
    "user", "kunde", "customer", "dear user", "dear kunde", "dear customer",
    "valued customer", "client"
]

def detect_generic_username(email_text):
    """
    Analyserer e-postteksten for å finne generiske henvendelser.
    
    Returnerer et dictionary med:
      - count: antall unike generiske uttrykk funnet
      - terms: en liste over de funnede uttrykkene
    """
    found_terms = set()
    lower_text = email_text.lower()
    
    for term in GENERIC_TERMS:
        pattern = re.compile(r'\b' + re.escape(term) + r'\b', re.IGNORECASE)
        if pattern.search(email_text):
            found_terms.add(term)
    
    # Sjekk også om greeting inneholder en e-postadresse, f.eks. "Dear someone@example.com"
    email_pattern = re.compile(r'dear\s+([\w\.-]+@[\w\.-]+)', re.IGNORECASE)
    email_match = email_pattern.search(email_text)
    if email_match:
        found_terms.add(email_match.group(1))
    
    return {
        "count": len(found_terms),
        "terms": list(found_terms)
    }


if __name__ == "__main__":
    test_email = (
        "Dear customer,\n\n"
        "Your account has been updated. If you have any questions, please contact support.\n\n"
        "Sincerely,\n"
        "Company\n\n"
        "P.S. If you do not recognize this email, please disregard it."
    )
    detection = detect_generic_username(test_email)
    print("Generic username detection:", detection)
   
