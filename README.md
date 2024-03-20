
# Security Assessment Tool

This Python script is a security assessment tool designed for scanning and analyzing the security posture of target systems. It includes functionalities such as port scanning, vulnerability scanning, log analysis, and password strength checking to provide security assessments.

## Features

- **Port Scanning**: Scan a range of TCP ports on a target system to identify open ports and services.
- **Banner Grabbing**: Attempt to grab banners from open ports to determine service details.
- **Vulnerability Scanning**: Utilize the Vulners API to search for known vulnerabilities associated with services discovered during port scanning.
- **Log Analysis**: Analyze Windows Security event logs to detect suspicious activities, particularly multiple failed login attempts.
- **Password Strength Analysis**: Assess the strength of passwords based on various criteria such as length, presence of special characters, numbers, uppercase, and lowercase letters.
- **Report Generation**: Generate a detailed security assessment report summarizing the findings from port scanning, vulnerability scanning, log analysis, and password strength analysis.

## How to Use

### Prerequisites

- Python 3.x installed on your system.
- Required Python packages installed (`pip install -r requirements.txt`).

### Usage

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/your_username/security-assessment-tool.git
    ```

2. Navigate to the project directory:

    ```bash
    cd security-assessment-tool
    ```

3. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

4. Run the script with the desired command-line arguments:

    ```bash
    python security_assessment.py -t <target> -s <start_port> -e <end_port> -f <thread_no> -o <output_filename>
    ```

    - Replace `<target>` with the IP address or domain name of the target system.
    - Replace `<start_port>` and `<end_port>` with the range of ports to scan.
    - Replace `<thread_no>` with the number of threads to use for scanning (optional, default is 5).
    - Replace `<output_filename>` with the desired filename for the security assessment report.

5. Follow the prompts to input passwords for password strength analysis.

6. Once the scan is complete, the script will generate a detailed security assessment report in the specified output file.

## Example

```bash
python security_assessment.py -t 192.168.1.100 -s 1 -e 1000 -f 10 -o report.txt
```

This command will scan ports 1 to 1000 on the target IP address `192.168.1.100` using 10 threads and generate a report named `report.txt`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Feel free to customize the README according to your project's specific requirements and add any additional information or instructions as needed.
