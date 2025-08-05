# Zacksaw

## Overview
The Java Vulnerability Analyzer is a VSCode extension designed to perform static code analysis on Java source code. It identifies potential vulnerabilities and coding issues, helping developers maintain high-quality and secure code.

## Features
- **Vulnerability Detection**: Analyzes Java files for common coding vulnerabilities such as:
  - Constant naming conventions
  - Excessive nesting
  - Hardcoded sensitive information
- **Real-time Analysis**: Automatically triggers analysis on every file save event, ensuring immediate feedback on code quality.
- **Diagnostic Reporting**: Issues found during analysis are surfaced in the Problems panel, providing developers with actionable insights.
- **Customizable Rules**: Load and manage vulnerability detection rules from a JSON configuration file.