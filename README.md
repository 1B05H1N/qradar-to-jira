# QRadar to Jira Integration

A robust, one-way integration that pulls offenses from IBM QRadar and creates issues in Jira, with duplicate prevention, error handling, and strong security practices.

---

## ⚡ Quick Start

```bash
git clone https://github.com/1B05H1N/qradar-to-jira.git
cd qradar-to-jira
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env  # Edit .env with your credentials
python qradar_to_jira.py
```

---

## Features

- Automatically creates Jira issues for open QRadar offenses
- Maps QRadar severity to Jira priority
- Handles SSL certificates and weak certificate warnings
- Configurable logging with rotation
- Test mode for safe testing
- Duplicate detection to prevent duplicate tickets
- Custom field mapping for flexible integration
- Error handling and recovery mechanisms
- Security best practices implementation

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/1B05H1N/qradar-to-jira.git
   cd qradar-to-jira
   ```

2. **Set up a Virtual Environment (Recommended):**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install required packages:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   - Copy `.env.example` to `.env` and fill in your QRadar and Jira credentials.

5. **Run the script:**

   ```bash
   python qradar_to_jira.py
   ```

---

## API Token Requirements

### QRadar SEC Token

Follow IBM's official documentation: [Creating an authentication token](https://www.ibm.com/docs/en/qradar-common?topic=forwarding-creating-authentication-token)

### Jira API Token

Follow Atlassian's official documentation: [Manage API tokens for your Atlassian account](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)

---

## ⚠️ DISCLAIMER

### IMPORTANT: USE AT YOUR OWN RISK

This integration script is provided as-is, without any warranties or guarantees. Before using this script in a production environment:

1. **Test Thoroughly**: 
   - Test in a non-production environment first
   - Verify all API endpoints and authentication methods
   - Test with different types of offenses and configurations
   - Validate SSL/TLS settings in your environment

2. **Environment Differences**:
   - Your QRadar and Jira versions may differ from the tested versions
   - API endpoints and authentication methods may vary
   - Custom fields and configurations may need adjustment
   - Network and security settings may affect functionality

3. **No Guarantees**:
   - The script may not work in your specific environment
   - Updates to QRadar or Jira may break functionality
   - Security settings may prevent the script from working
   - Custom configurations may require modifications

4. **Responsibility**:
   - You are responsible for testing and validating the script
   - You are responsible for maintaining and updating the script
   - You are responsible for security and access controls
   - You are responsible for any data loss or issues

5. **Support**:
   - No official support is provided
   - Issues should be reported via GitHub
   - Community support may be available
   - Updates are not guaranteed

By using this script, you acknowledge that:
- You have read and understood this disclaimer
- You accept all risks associated with using this script
- You will test thoroughly before production use
- You are responsible for any issues that arise

---

## One-Way Integration

This is a **one-way** integration that:
- **Pulls** from QRadar (reads offenses)
- **Pushes** to Jira (creates issues)
- **Does not** automatically sync status changes
- **Does not** automatically close issues

### Manual Steps Required

You must manually:
1. **Close QRadar Offenses**:
   - After resolving the issue in QRadar
   - Through the QRadar console
   - Following your organization's procedures

2. **Close Jira Issues**:
   - After resolving the issue in Jira
   - Through the Jira interface
   - Following your organization's workflow

3. **Status Management**:
   - Keep track of both platforms
   - Update status in both systems
   - Follow your organization's procedures

### Future Enhancements

Bidirectional synchronization may be added in future versions:
- Automatic status updates
- Two-way ticket syncing
- Automated closure workflows
- Real-time updates

For now, this connector focuses on reliable one-way integration from QRadar to Jira.

---

## Configuration

### Environment Variables

Create a `.env` file in the script directory:

```bash
# Required
QRADAR_URL=https://your-qradar/api/siem/offenses
QRADAR_TOKEN=your-sec-token
JIRA_URL=https://your-domain.atlassian.net
JIRA_USERNAME=your-email
JIRA_API_TOKEN=your-api-token
PROJECT_KEY=your-project-key

# Optional
LOG_LEVEL=INFO
MAX_LOG_SIZE=10
BACKUP_COUNT=5
TEST_MODE=false
SSL_VERIFY=true
SSL_CERT_PATH=/path/to/cert
SSL_SECURITY_LEVEL=high  # high, medium, low

# Error Handling
MAX_RETRIES=3
RETRY_DELAY=5
CHECKPOINT_FILE=.checkpoint
```

### Custom Fields Configuration

The script uses custom fields to store QRadar-specific information in Jira. Configure your custom fields:

1. Create custom fields in your Jira instance:
   - Go to Jira Administration > Issues > Custom Fields
   - Create fields with appropriate types:
     * Text fields for IDs and descriptions
     * URL fields for links
     * Date fields for timestamps
     * Select fields for categories/severity
     * Checkbox fields for boolean values

2. Find your custom field IDs:
   - In Jira Administration, go to Issues > Custom Fields
   - Find each field and note its ID (e.g., customfield_10091)

3. Update the `JIRA_FIELDS` dictionary in the script:

```python
JIRA_FIELDS = {
    "priority": {
        "1": "Highest",
        "2": "High",
        "3": "Medium",
        "4": "Low",
        "5": "Lowest"
    },
    "custom_fields": {
        "qradar_id": "your_customfield_id",
        "qradar_link": "your_customfield_id",
        # Add or remove fields as needed
    }
}
```

---

## Security

### Required Permissions

1. **QRadar Access (Read-Only)**
   - API access token with read-only permissions to offenses
   - No write permissions required
   - Access to `/api/siem/offenses` endpoint

2. **Jira Access (Write)**
   - API token with write permissions to the target project
   - Project admin or higher permissions recommended
   - Ability to create and update issues
   - Access to custom fields
   - Required Jira Permissions:
     * Create Issues
     * Edit Issues
     * Add Comments
     * View Project
     * Browse Projects
     * Create Attachments (if needed)
     * Transition Issues (if workflow changes are needed)
     * Assign Issues (if auto-assignment is configured)
     * Resolve Issues (if auto-resolution is configured)

### Security Best Practices

1. **API Tokens**
   - Use separate tokens for QRadar and Jira
   - Regularly rotate API tokens (recommended every 90 days)
   - Store tokens securely in `.env` file
   - Set strict file permissions: `chmod 600 .env`

2. **Network Security**
   - Use SSL/TLS for all connections (enabled by default)
   - Configure firewalls to allow only necessary traffic
   - Use VPN or private network when possible
   - Monitor for unusual API activity

3. **Access Control**
   - Use principle of least privilege
   - Regularly audit API token usage
   - Monitor for unauthorized access attempts
   - Implement IP whitelisting if possible

---

## Error Handling

The script includes robust error handling and recovery mechanisms:

1. **Transient Errors**
   - Automatic retry for network timeouts
   - Exponential backoff for rate limits
   - Configurable retry attempts and delays
   - Logs all retry attempts

2. **Permanent Errors**
   - Detailed error logging
   - Graceful failure handling
   - Error categorization (network, auth, API, etc.)
   - Exit codes for different error types

3. **Recovery Mechanisms**
   - Checkpoint system to track processed offenses
   - Ability to resume from last successful sync
   - Skip already processed offenses
   - Manual recovery options

4. **Monitoring and Alerts**
   - Detailed error logs
   - Success/failure metrics
   - Alert thresholds for error rates
   - Integration with monitoring systems

---

## Automation

### Wrapper Script

Create a wrapper script `run_qradar_to_jira.sh`:

```bash
#!/bin/bash

# Set the working directory
cd /path/to/qradar-to-jira

# Load environment variables
source .env

# Run the script and log output
python qradar_to_jira.py >> /var/log/qradar_to_jira/cron.log 2>&1
```

### Cron Configuration

Add to crontab (run every 15 minutes):

```bash
*/15 * * * * /path/to/run_qradar_to_jira.sh
```

### Log Directory Setup

```bash
sudo mkdir -p /var/log/qradar_to_jira
sudo chown youruser:yourgroup /var/log/qradar_to_jira
```

---

## Testing

1. Enable test mode in your `.env`:

```bash
TEST_MODE=true
```

2. Run the script:

```bash
python qradar_to_jira.py
```

3. The script will:
   - Show a preview of the first offense
   - Ask for confirmation before creating the issue
   - Create only one test issue
   - Show detailed logs

---

## Troubleshooting

1. Check the log file:

```bash
tail -f qradar_to_jira.log
```

2. Common issues:
   - SSL certificate errors: Set `SSL_VERIFY=false` or provide correct certificate path
   - Authentication errors: Verify API tokens and credentials
   - Custom field errors: Check field IDs and types in Jira
   - Network issues: Verify connectivity to QRadar and Jira
   - Rate limiting: Adjust retry settings in .env
   - Checkpoint errors: Verify checkpoint file permissions

3. Enable debug logging:

```bash
LOG_LEVEL=DEBUG
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

## License

This project is licensed under the MIT License - see the LICENSE file for details. 