import re

URGENCY_WORDS = [
    # Norske ord/uttrykk:
    "haster", "umiddelbart", "nå", "viktig", "haste", "straks",
    "umiddelbar", "umiddelbar handling", "vær rask", "svar umiddelbart",
    "kontakt straks", "snarest", "svar nå", "handling kreves", "reaksjon påkrevd",
    
    # Engelske ord/uttrykk:
    "urgent", "account suspended", "verify now", "act fast", "final warning", "last chance",
    "act immediately", "do not delay", "immediate action", "limited time", "time sensitive",
    "emergency", "rush", "prompt response", "respond now", "critical", "immediate response", "time-critical"
]

def detect_urgency(email_text):
    """
    Returnerer hvor mange ganger ord/fraser fra URGENCY_WORDS dukker opp.
    """
    email_text = email_text.lower()
    urgency_count = sum(len(re.findall(rf"\b{word}\b", email_text)) for word in URGENCY_WORDS)
    return urgency_count

def get_urgency_words(email_text):
    """
    Returnerer en liste (eller et sett) med unike ord fra URGENCY_WORDS 
    som faktisk dukker opp i e-posten.
    """
    found_words = set()
    email_text_lower = email_text.lower()

    for word in URGENCY_WORDS:
        # Bruk en case-insensitive regex for å se om 'word' dukker opp
        pattern = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
        if pattern.search(email_text_lower):
            found_words.add(word)
    return list(found_words)

if __name__ == "__main__":
    test_email = "Haster! Kontoen din blir stengt umiddelbart hvis du ikke verifiserer nå."
    print("Urgency score:", detect_urgency(test_email))
    print("Words found:", get_urgency_words(test_email))