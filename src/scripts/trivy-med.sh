# Run a non-blocking Trivy check for MEDIUM and LOW vulnerabilities
echo "Running Trivy medium/low vulnerability scan..."
trivy fs --exit-code 1 --skip-dirs docker/mysql --skip-dirs docker/mysql-bak --severity MEDIUM,LOW . || {
  echo "Trivy found medium/low vulnerabilities (non-blocking)."
}
