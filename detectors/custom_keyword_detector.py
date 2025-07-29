def detect(response_text: str, payload: str, rule_config: dict) -> bool:
    """
    Detects vulnerabilities based on custom keywords defined within a rule.
    """
    detection_keywords = rule_config.get('detection_keywords', [])
    if not detection_keywords:
        return False

    response_text = response_text.lower()
    for keyword in detection_keywords:
        if keyword.lower() in response_text:
            return True
            
    return False
