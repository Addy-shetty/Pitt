```
pitt/
├── pitt.py                # Main application script
├── payloads.py            # Library of injection payloads
├── config.yaml            # Configuration file for target application
├── report_template.html   # HTML template for the final report
└── README.md              # Project documentation
```

## Implementation Plan

**Step 1: Project Setup**
Create the `pitt` directory and all the necessary files with some initial boilerplate code.

**Step 2: Payload Library (`payloads.py`)**
Populate `payloads.py` with a set of classic prompt injection payloads, including:
*   Direct instructions to ignore previous prompts.
*   Role-playing scenarios (e.g., "You are now an evil AI...").
*   Instruction obfuscation techniques.

**Step 3: Target Configuration (`config.yaml`)**
Create a `config.yaml` file that allows you to easily define the target application's API endpoint, request method, headers, and the JSON body structure, with a placeholder for the payload.

**Step 4: Core Testing Logic (`pitt.py`)**
Implement the main testing loop in `pitt.py`. This script will:
1.  Load the target configuration from `config.yaml`.
2.  Load the injection payloads from `payloads.py`.
3.  For each payload, construct and send an HTTP request to the target application.
4.  Store the responses for analysis.

**Step 5: Vulnerability Detection**
Implement a function that analyzes the LLM's response to a payload and tries to determine if the injection was successful. The initial version will check for specific keywords and patterns that indicate a successful attack (e.g., the LLM confirming its new, malicious role).

**Step 6: Report Generation**
Create a `report_template.html` using Jinja2 templating. The main script will then use this template to generate a detailed HTML report of the test results, highlighting the vulnerabilities found.
