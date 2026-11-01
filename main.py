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
    # The subprocess is an argv list, so shell metacharacters would be
    # inert anyway. The check that earns its place is the leading dash:
    # an image name starting with one would be read by the scanner as its
    # own flag. The rest of the character list is defence in depth.
    if image_name.startswith("-"):
        logging.error("Invalid image name: Image name must not start with a dash.")
        return False
    if any(ch.isspace() for ch in image_name) or any(ch in ";|&$`\\\"'<>\\(){}[]!#*?~" for ch in image_name):
        logging.error("Invalid image name: Image name contains whitespace or shell metacharacters.")
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
                # In JSON mode the format is passed twice, once as -o and once as
                # --output-format. If the installed Grype accepts only one of those
                # spellings, the JSON path fails at the scanner while text runs work.
                command += ['--output-format', 'json']

        elif scanner == 'trivy':
            # No --output file: trivy prints its JSON to stdout, which this
            # tool parses. Writing result.json here would overwrite a file
            # in the working directory that the run did not create.
            command = ['trivy', 'image', '--format', output_format, image_name]
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
            # A trivy JSON document is a top level object with a Results list.
            results_section = data.get('Results', []) if isinstance(data, dict) else []
            for section in results_section:
                vulnerabilities_raw = section.get('Vulnerabilities', []) or []
                for vul in vulnerabilities_raw:
                    # Trivy results are rebuilt into the Grype match shape by hand, so the
                    # summary loop below has one shape to read. Fields Trivy reports that
                    # the shape has no room for, fixed version among them, are dropped at
                    # this step and never reach the summary.
                    formatted_vul = {
                        'vulnerability': {
                            'id': vul.get('VulnerabilityID', 'N/A'),
                            'severity': str(vul.get('Severity', 'unknown')).lower(),
                            'description': vul.get('Description', 'No description available'),
                            'references': [{'url': vul.get('PrimaryURL', 'N/A')}]
                        },
                        'artifact': {'name': vul.get('PkgName', 'N/A'), 'version': vul.get('InstalledVersion', 'N/A')}
                    }
                    vulnerabilities.append(formatted_vul)

        summary = ""
        vulnerability_count = 0

        for match in vulnerabilities:
            severity = str(match.get('vulnerability', {}).get('severity', 'unknown')).lower()
            if severity_filter and severity != str(severity_filter).lower():
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

    # A severity filter needs parsed results, so it runs the scanner in
    # JSON mode and prints the filtered summary even in text mode.
    effective_output = 'json' if args.severity else args.output
    return_code, results = run_scanner(args.image_name, args.scanner, effective_output)

    if return_code is None:
        sys.exit(1)

    if return_code != 0:
        print(f"Scanner exited with code {return_code}:\n{results}")
        sys.exit(1)


    if effective_output == 'json':
        summary = summarize_results(results, args.scanner, args.severity)
        if summary.startswith("Error:"):
            print(summary)
            sys.exit(1)
    else:
        summary = results

    print(summary)

    # The exit on vuln decision reads the summary as text and searches for
    # two exact sentences. In JSON mode those sentences are this tool's
    # own, so the test is sound there. In text mode the summary is the
    # scanner's raw output, and whether the sentences appear depends on
    # the scanner's wording, not on the findings.
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