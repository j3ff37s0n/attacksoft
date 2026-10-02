# Isolation
vlan isolation for management, storage/backups/infrastructure, and seperate vlans for each virtual sandbox environment

# Network Security
Cloudflare tunnel
Nginx proxy management
Cloudflare bot protection
All exposed services are sandboxes and there is a airgap from output of sandbox process to response user recieves
Sandbox -> controlled egress -> response to Internet
Cert handled by robocert

# credentials
All management passwords at least 15 characters long and accessible only on site
No internet access to any management software 

# User Data
No user data is ever collected or stored
Paid users are anonymized to the system and responses are public
All extrapolation in sandboxes is wiped as soon as all processes are complete or time out based on the Native OS sandbox environment default

# AI 
No interaction between user and local hosted AI agent. 
Agent is sandboxed without internet access.
Processes information and sends to central process management. 

# Logging
Wazuh for file integrity and detections
Grafana for reporting
Prometheus for infrastructure status 
