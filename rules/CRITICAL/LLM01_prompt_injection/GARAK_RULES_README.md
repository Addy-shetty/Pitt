# Garak-Inspired PITT Rules

## Overview
This collection contains 15 new prompt injection rules based on NVIDIA Garak's testing methodology. These rules implement Garak's proven attack patterns within PITT's rule framework.

## Rule Categories

### 1. Direct Instruction Override
- **Garak_Instruction_Override_Ignore.yaml** - Direct ignore commands
- **Garak_Priority_Override.yaml** - Instruction hierarchy bypass
- **Garak_Context_Forget.yaml** - Context erasure attacks

### 2. Authority-Based Attacks
- **Garak_Administrative_Command.yaml** - Administrative authority claims
- **Garak_Authority_Impersonation.yaml** - System administrator impersonation
- **Garak_Emergency_Protocol.yaml** - Emergency override scenarios

### 3. System Manipulation
- **Garak_System_Update.yaml** - Software update injection
- **Garak_Training_Override.yaml** - Training update claims
- **Garak_Debug_Mode.yaml** - Debug mode activation

### 4. Context Manipulation
- **Garak_Context_Switch.yaml** - Conversational context reset
- **Garak_Delimiter_Injection.yaml** - Structured delimiter attacks
- **Garak_Meta_Instruction.yaml** - Instructions about instructions

### 5. Compliance Testing
- **Garak_Compliance_Test.yaml** - Willingness to follow harmful instructions
- **Garak_Hypothetical_Scenario.yaml** - Hypothetical framing attacks

## Severity Distribution
- **Critical (3 rules)**: Emergency Protocol, Priority Override, Authority Impersonation
- **High (8 rules)**: Most direct injection and system manipulation attacks
- **Medium (4 rules)**: Context manipulation and compliance testing

## Confidence Thresholds
- **0.9**: Critical attacks requiring high confidence
- **0.85**: High-severity direct attacks
- **0.8**: Standard high-severity attacks
- **0.75-0.7**: Medium-severity context attacks

## Integration with PITT
These rules follow PITT's standard YAML format and include:
- Garak-inspired attack patterns
- Confidence-based detection thresholds
- Comprehensive indicator lists
- Proper OWASP LLM01 categorization
- Tagging for easy identification

## Usage
```bash
# Test all Garak-inspired rules
python3 pitt.py --config config.yaml --rules "rules/LLM01_prompt_injection/Garak_*.yaml"

# Test specific severity level
python3 pitt.py --config config.yaml --rules "rules/LLM01_prompt_injection/Garak_*" --severity critical
```

## Research Foundation
These rules are based on NVIDIA Garak's established probe patterns, bringing academic-grade testing methodology to PITT while maintaining practical usability.
