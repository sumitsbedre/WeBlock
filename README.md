# WeBlock - Cybersecurity Website Analysis Tool 🌐🔐

## Overview

**WeBlock** is a beginner-friendly, full-stack web application designed to help users assess the safety of websites by providing an easy-to-understand analysis using Nmap. The tool checks for phishing risks, HTTPS security, blacklisting status, and other potential threats. It simplifies cybersecurity and makes it accessible for users with no technical background.

## Features

`WeBlock` provides:

- **Website Safety Analysis**: Checks for common phishing patterns, HTTPS usage, and blacklisting status.
- **Nmap Scan**: Conducts a detailed network scan to detect vulnerabilities and open ports on the target website.
- **Download Scan Results**: Allows users to download the results of both the safety analysis and Nmap scan as a `.txt` file.
- **User-Friendly Interface**: Attractive and simple design with clear results and easy navigation.
- **Ethical Data Handling**: Temporary data files are created during analysis and deleted after use, ensuring privacy.

## Prerequisites

- Python 3.x
- Required Python libraries: `flask`, `flask_wtf`, `wtforms`, `requests`, `subprocess`, `flask_mysqldb`
- XAMPP application (for MySQL and Apache server)
- A compatible browser (Chrome, Firefox, etc.)
- A code editor (VS Code recommended)
- Strong internet connection

## Installation

1. Install XAMPP and start Apache and MySQL in the XAMPP Control Panel.
2. Install the required Python libraries using `pip`:
   ```sh
   pip install flask flask_wtf wtforms requests flask_mysqldb
   ```

## Clone this repo
 ```sh
git clone https://github.com/sumitsbedre/weblock.git
cd weblock

   ```

## Usage

1. Start XAMPP and ensure Apache and MySQL are running.
2. Navigate to your project folder and open it in a code editor (e.g., VS Code).
3. Create a new database in PHPMyAdmin (http://localhost/phpmyadmin) called weblock.
4. Run the Flask application by executing the following command in the project folder:
```sh
python app.py
```
This will start the web application, and you can access it in your browser at `http://127.0.0.1:5000`.

## Customization

You can customize WeBlock by adding additional features or modifying existing ones. Here are some suggestions:

- Add More Scan Options: You can enhance the Nmap scan by adding new scan types or more detailed checks.
- Improve UI: Modify the HTML/CSS to add new sections or change the look of the website.
- Enhance Analysis: Add more website safety checks or integrate with additional security APIs to increase the accuracy of the analysis.
- Add User Authentication: Implement user login/registration if you want to allow users to save their scan results or history.

## Copyrights

You can use the website as of you want using as of customized format. But Please DO NOT make any claims being as its own.Respect the work.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request with any changes or improvements.
