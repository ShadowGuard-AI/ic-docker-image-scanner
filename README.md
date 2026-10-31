![Banner](banner.png)

# ic-Docker-Image-Scanner
Scans a Docker image for known vulnerabilities using the `grype` or `trivy` command-line tool installed on your machine. In JSON mode, and whenever `--severity` is given, it prints a summary of the matches. In plain text mode with no severity filter it prints the scanner output as the scanner produced it.

This tool does not read Terraform, CloudFormation, or Kubernetes files, and it does not check infrastructure as code. It scans one named container image per run.

## Install
`git clone https://github.com/ShadowGuardAI/ic-docker-image-scanner`

Install `grype` or `trivy` separately and put it on your PATH. This script calls whichever one you pick; neither scanner is installed by the clone.

## Usage
`python3 main.py [params] image_name`

## Parameters
- `image_name`: The name of the Docker image to scan. Required. Names starting with a dash, or containing whitespace or shell metacharacters, are rejected.
- `-h`: Show help message and exit
- `--scanner`: The vulnerability scanner to use, `grype` or `trivy`. Defaults to grype.
- `--output`: The output format, `json` or `text`. Defaults to text.
- `--severity`: Filter results by severity. When given, the scanner runs in JSON mode and the filtered summary is printed, in both output modes.
- `--exit-on-vuln`: Exit with a non-zero code if vulnerabilities are found.

A scan that cannot be parsed, for example a scanner that returns output that is not valid JSON in JSON mode, exits 1 instead of printing an error as if it were a summary. The tool writes no result file of its own.

## License
Copyright (c) ShadowGuardAI
