# VulTra

## Overview
The VulTra is a VScode extension designed to detect potential vulnerabilities in Java code automatically. This tool assists developers by providing real-time vulnerability analysis,code violation, and automatic fixes via AI-powered suggestions. The primary goal is to ensure that developers write secure code, avoid common vulnerabilities, and push clean, vulnerability-free code to production.

## How it works?

### 1. Vulnerability Detection:
  The extension continuously monitors the workspace. Each time a user saves a Java file, the extension performs an analysis of the code. The following checks are done using regular expressions (regex patterns) for common vulnerabilities/violations:	
  - **SQL Injection:** Detects unsafe SQL queries using Statement objects with string concatenation.
  - **XSS (Cross-Site Scripting):** Flags cases where user input is not escaped properly before being printed in the response.
  - **Hardcoded Secrets:** Identifies sensitive data (e.g., passwords, API key) directly written into the code.
  - **Naming conventions:** Checks that constants follow proper naming conventions (e.g., UPPER_CASE_WITH_UNDERSCORES).
  - **Excessive Nesting:** Identifies code blocks with excessive nesting of control structures, which may benefit from refactoring.
  
  Additionally, the extension performs semantic analysis on loggers (like LOGGER.info()) to ensure sensitive information (e.g., user credentials, session IDs) is not accidentally logged. 

### 2. Issue Reporting:
  Detected vulnerabilities are displayed in a panel within the IDE. For each issue, the following information is provided:
  
      - Filename
      - Line Number
      - Issue Description
      - Suggested Fix
    
### 3. AI-Driven Fix:
  When an issue is detected, users can click the "**Generate AI Fix**" button. The selected vulnerable code, along with the description of the issue, is sent to internally hosted(if any) AI model (GPT/Claude). 
  The AI generates a solution by either:

    a. Modifying the existing code to remove the vulnerability
    b. Suggesting an alternative approach to mitigate the issue
    
### 4.Apply Fix:
  Love what the AI served? Now review the fix and smash that Apply Fix button; it automatically updates the code.

---

## How to run/test the extension?
1. Clone the repo
```
git clone <this repo>
cd cd VulTra
```

2. Compile the extension:
```
npm run compile
```

3. Debug in VS Code:
```
Press F5 or go to Run & Debug
Select "Launch Extension"
This opens a new VS Code window with your extension loaded
```

4. Test the commands:
```
Press Ctrl+Shift+P to open Command Palette
Type "Java Security" to see your commands
Or use Ctrl+Alt+V on a Java file
```

## License and Attribution

This project uses the [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) model which is licensed under the Apache License 2.0.

The full license text can be found in the [LICENSE](licenses/model/LICENSE.txt) file.