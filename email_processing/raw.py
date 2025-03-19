from email import message_from_bytes

def get_plain_text(raw_email_bytes):
    """
    Returnerer e-postens tekstinnhold (text/plain) hvis tilgjengelig.
    Hvis ikke, returneres en tom streng.
    """
    msg = message_from_bytes(raw_email_bytes)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        return payload.decode('utf-8', errors='ignore')
                    except Exception:
                        return payload.decode('latin-1', errors='ignore')
    else:
        if msg.get_content_type() == "text/plain":
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    return payload.decode('utf-8', errors='ignore')
                except Exception:
                    return payload.decode('latin-1', errors='ignore')
    return ""

def get_email_body(raw_email_bytes):
    """
    Henter ut e-postens brødtekst fra rå e-postdata (bytes).
    Henter både 'text/plain' og 'text/html' deler, og forsøker å dekode med UTF-8 (med fallback til Latin-1 om nødvendig).

    Args:
        raw_email_bytes (bytes): Rå e-postdata.

    Returns:
        str: Sammenkoblet brødtekst fra e-posten.
    """
    msg = message_from_bytes(raw_email_bytes)
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                # Prøv å hente payload med dekoding
                payload = part.get_payload(decode=True)
                if payload is None:
                    # Dersom get_payload(decode=True) ikke returnerer noe, hentes den direkte
                    payload = part.get_payload()
                    if isinstance(payload, str):
                        body_parts.append(payload)
                else:
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                    except Exception:
                        text = payload.decode('latin-1', errors='ignore')
                    body_parts.append(text)
    else:
        payload = msg.get_payload(decode=True)
        if payload is None:
            payload = msg.get_payload()
            if isinstance(payload, str):
                body_parts.append(payload)
        else:
            try:
                text = payload.decode('utf-8', errors='ignore')
            except Exception:
                text = payload.decode('latin-1', errors='ignore')
            body_parts.append(text)

    return "\n".join(body_parts)