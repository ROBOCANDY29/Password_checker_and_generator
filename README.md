# Password Strength Analyzer with Integrated Password Generation and Breach Detection

## Overview

This project is a comprehensive tool designed to help users create, analyze, and manage secure passwords. It features password strength analysis, secure password generation, and breach detection using the **HaveIBeenPwned API**. With increasing cyber threats, this tool aims to enhance user security by preventing the use of weak or compromised passwords.

## Features

- **Password Strength Analyzer**: Evaluates passwords based on length, capital and lowercase letters, numeric and special characters.
- **Password Breach Detection**: Checks passwords against the HaveIBeenPwned database to detect if they've been compromised in known breaches.
- **Secure Password Generation**: Automatically generates strong, random passwords adhering to various security standards.
- **Graphical User Interface (GUI)**: A user-friendly interface built with **Tkinter** for easy interaction.
- **Machine Learning Integration**: Uses an MLPClassifier neural network to predict password strength based on input features.

## Requirements

To run this project, you need the following dependencies installed:

- Python 3.x
- Tkinter (for the GUI)
- Requests (for API integration)
- Scikit-learn (for machine learning models)
- Numpy & Pandas (for data handling)
- HaveIBeenPwned API key (optional, for breach detection)

To install the required libraries, you can use the following command:
```bash
pip install -r requirements.txt
