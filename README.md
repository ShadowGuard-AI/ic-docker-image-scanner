# ic-Docker-Image-Scanner
Scans Docker images for known vulnerabilities using `grype` or `trivy` command-line tools. Presents results in a summarized format highlighting critical and high-severity issues. Requires `subprocess` to execute external scanner and `json` to parse output. - Focused on Automates verification of infrastructure-as-code (IaC) configurations against predefined security and compliance policies. Checks for misconfigurations in Terraform, CloudFormation, or Kubernetes manifests before deployment. Enables shift-left security by identifying vulnerabilities early in the development lifecycle.

## Install
`git clone https://github.com/ShadowGuardAI/ic-docker-image-scanner`

## Usage
`./ic-docker-image-scanner [params]`

## Parameters
- `-h`: Show help message and exit
- `--scanner`: No description provided
- `--output`: The output format. Defaults to text.
- `--severity`: Filter results by severity. If None, shows all severities
- `--exit-on-vuln`: Exit with a non-zero code if vulnerabilities are found.

## License
Copyright (c) ShadowGuardAI
