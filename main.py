import argparse
import subprocess
import json
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Scans Docker images for vulnerabilities using Grype or Trivy.')
    parser.add_argument('image_name', help='The name of the Docker image to scan.')
    parser.add_argument('--scanner', choices=['grype', 'trivy'], default='grype',
                        help='The vulnerability scanner to use (grype or trivy). Defaults to grype.')
    parser.add_argument('--output', choices=['json', 'text'], default='text',
                        help='The output format. Defaults to text.')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'negligible', 'unknown'], default=None,
                        help='Filter results by severity. If None, shows all severities')
    parser.add_argument('--exit-on-vuln', action='store_true', help='Exit with a non-zero code if vulnerabilities are found.')
    return parser


def validate_image_name(image_name):
    """
    Validates the Docker image name.

    Args:
        image_name (str): The Docker image name to validate.

    Returns:
        bool: True if the image name is valid, False otherwise.
    """
    if not isinstance(image_name, str) or not image_name:
        logging.error("Invalid image name: Image name must be a non-empty string.")
        return False
    return True


def run_scanner(image_name, scanner, output_format):
    """
    Runs the specified vulnerability scanner on the given Docker image.

    Args:
        image_name (str): The name of the Docker image to scan.
        scanner (str): The vulnerability scanner to use ('grype' or 'trivy').
        output_format (str): The output format ('json' or 'text').

    Returns:
        tuple: A tuple containing the return code and the output of the scanner.  Returns None, None on error.
    """
    try:
        if scanner == 'grype':
            command = ['grype', image_name, '-o', output_format]
            if output_format == 'json':
                command += ['--output-format', 'json']

        elif scanner == 'trivy':
            command = ['trivy', 'image', '--format', output_format, image_name]
            if output_format == 'json':
                command += ['--output', 'result.json']
        else:
            logging.error(f"Invalid scanner specified: {scanner}")
            return None, None

        logging.info(f"Running command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # check=False for manual error handling

        if result.returncode != 0:
            logging.error(f"Scanner failed with error: {result.stderr}")
            return result.returncode, result.stderr
        
        return result.returncode, result.stdout

    except FileNotFoundError:
        logging.error(f"Error: {scanner} not found. Please ensure it is installed and in your PATH.")
        return None, None
    except Exception as e:
        logging.exception(f"An unexpected error occurred while running the scanner: {e}")
        return None, None


def summarize_results(results, scanner, severity_filter=None):
    """
    Summarizes the vulnerability scan results, highlighting critical and high-severity issues.

    Args:
        results (str): The JSON output from the vulnerability scanner.
        scanner (str): The vulnerability scanner used ('grype' or 'trivy').
        severity_filter (str, optional): Filter results by severity ('critical', 'high', 'medium', 'low', 'negligible', 'unknown'). Defaults to None.

    Returns:
        str: A summarized report of the vulnerabilities.
    """

    try:
        vulnerabilities = []
        if scanner == 'grype':
            data = json.loads(results)
            vulnerabilities = data.get('matches', [])
        elif scanner == 'trivy':
            data = json.loads(results)
            results_section = data[0].get('Results', []) #Trivy JSON format is different
            if results_section: # Check if the 'Results' section is not empty
                vulnerabilities_raw = results_section[0].get('Vulnerabilities', [])
                # Adapt Trivy JSON to match Grype vulnerability format for consistency
                for vul in vulnerabilities_raw:
                    formatted_vul = {
                        'vulnerability': {
                            'id': vul['VulnerabilityID'],
                            'severity': vul['Severity'].lower(),  # Normalize severity to lowercase
                            'description': vul['Description'],
                            'references': [{'url': vul['PrimaryURL']}]  # Simplify references
                        },
                        'artifact': {'name': vul['PkgName'], 'version': vul['InstalledVersion']} #added artifact name and version
                    }
                    vulnerabilities.append(formatted_vul)
            else:
                logging.warning("No vulnerabilities found in Trivy scan results.")

        summary = ""
        vulnerability_count = 0

        for match in vulnerabilities:
            severity = match.get('vulnerability', {}).get('severity', 'unknown')
            if severity_filter and severity != severity_filter:
                continue

            vulnerability_id = match.get('vulnerability', {}).get('id', 'N/A')
            description = match.get('vulnerability', {}).get('description', 'No description available')
            artifact_name = match.get('artifact', {}).get('name', 'N/A')
            artifact_version = match.get('artifact', {}).get('version', 'N/A')
            references = match.get('vulnerability', {}).get('references', [])
            reference_urls = [ref.get('url', 'N/A') for ref in references]

            summary += f"Vulnerability ID: {vulnerability_id}\n"
            summary += f"Severity: {severity}\n"
            summary += f"Package: {artifact_name} Version: {artifact_version}\n"
            summary += f"Description: {description}\n"
            summary += f"References: {', '.join(reference_urls)}\n"
            summary += "---\n"
            vulnerability_count += 1

        if not summary:
             if severity_filter:
                summary = f"No {severity_filter} vulnerabilities found."
             else:
                summary = "No vulnerabilities found."

        return f"Total Vulnerabilities Found: {vulnerability_count}\n\n{summary}"


    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON results: {e}")
        return "Error: Could not decode JSON results."
    except Exception as e:
        logging.exception(f"An error occurred while summarizing results: {e}")
        return "Error: Could not summarize results."


def main():
    """
    Main function to execute the Docker image scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not validate_image_name(args.image_name):
        sys.exit(1)

    return_code, results = run_scanner(args.image_name, args.scanner, args.output)

    if return_code is None:
        sys.exit(1)

    if return_code != 0:
        print(f"Scanner exited with code {return_code}:\n{results}")
        sys.exit(1)


    if args.output == 'json':
        summary = summarize_results(results, args.scanner, args.severity)
    else:
        summary = results

    print(summary)

    if args.exit_on_vuln and "No vulnerabilities found" not in summary:
         if "Total Vulnerabilities Found: 0" not in summary:
              sys.exit(1) # Exit with non-zero code if vulnerabilities are found



if __name__ == "__main__":
    # Example Usage:
    # 1. Scan an image with Grype and output to text: python main.py my-docker-image
    # 2. Scan an image with Trivy and output to JSON: python main.py my-docker-image --scanner trivy --output json
    # 3. Scan an image and only show critical vulnerabilities: python main.py my-docker-image --severity critical
    # 4. Fail if vulnerabilities are found: python main.py my-docker-image --exit-on-vuln
    main()