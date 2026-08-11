import os
import sys
import time
import logging
import requests
import urllib3
import traceback
import ssl
from datetime import datetime
from logging.handlers import RotatingFileHandler
from urllib3.util.ssl_ import create_urllib3_context
from dotenv import load_dotenv

# === CONFIGURATION ===
# Load environment variables from .env file
load_dotenv()

# === LOGGING CONFIGURATION ===
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
MAX_LOG_SIZE = int(os.getenv("MAX_LOG_SIZE", 10)) * 1024 * 1024  # Convert MB to bytes
BACKUP_COUNT = int(os.getenv("BACKUP_COUNT", 5))
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

# Configure logger with both file and console handlers
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, LOG_LEVEL))

# Add file handler with rotation
file_handler = RotatingFileHandler(
    'qradar_to_jira.log',
    maxBytes=MAX_LOG_SIZE,
    backupCount=BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(file_handler)

# Add console handler for immediate feedback
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(console_handler)

# === ERROR HANDLING CONFIGURATION ===
MAX_RETRIES = int(os.getenv("MAX_RETRIES", 3))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", 5))
CHECKPOINT_FILE = os.getenv("CHECKPOINT_FILE", ".checkpoint")

# === SSL CONFIGURATION ===
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() in ("1", "true", "yes")
SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", None)
SSL_SECURITY_LEVEL = os.getenv("SSL_SECURITY_LEVEL", "high").lower()  # high, medium, low

# === JIRA CONFIGURATION ===
# Custom field mappings - Update these with your actual Jira custom field IDs
JIRA_FIELDS = {
    "priority": {
        "1": "Highest",
        "2": "High",
        "3": "Medium",
        "4": "Low",
        "5": "Lowest"
    },
    "custom_fields": {
        "qradar_id": "customfield_10000",  # Critical: Used for duplicate detection
        "qradar_link": "customfield_10001",  # Link to QRadar offense
        "offense_severity": "customfield_10002",  # QRadar severity level
        "resolution": "customfield_10003",  # Issue resolution status
        "level_classification": "customfield_10004",  # Security level classification
        "manually_submitted": "customfield_10005",  # Manual submission flag
        "third_party": "customfield_10006",  # Third-party involvement flag
        "start_date": "customfield_10007",  # Offense start date
        "actual_end": "customfield_10008"  # Offense end date
    }
}

# === CLASSES ===
class CheckpointManager:
    """
    Manages checkpoint file for tracking processed offenses.
    
    This class handles:
    - Loading the last processed offense ID
    - Saving new checkpoint information
    - Determining if an offense should be processed
    
    The checkpoint system prevents duplicate ticket creation and allows
    the script to resume from where it left off in case of interruption.
    """
    def __init__(self, checkpoint_file):
        """Initialize checkpoint manager with file path."""
        self.checkpoint_file = checkpoint_file
        self.last_processed_id = None
        self.load_checkpoint()

    def load_checkpoint(self):
        """Load the last processed offense ID from checkpoint file."""
        try:
            if os.path.exists(self.checkpoint_file):
                with open(self.checkpoint_file, 'r') as f:
                    self.last_processed_id = int(f.read().strip())
                logger.info(f"Loaded checkpoint: Last processed offense ID: {self.last_processed_id}")
            else:
                logger.info("No checkpoint file found. Starting from beginning.")
        except Exception as e:
            logger.error(f"Error loading checkpoint: {str(e)}")
            self.last_processed_id = None

    def save_checkpoint(self, offense_id):
        """Save the last processed offense ID to checkpoint file."""
        try:
            with open(self.checkpoint_file, 'w') as f:
                f.write(str(offense_id))
            self.last_processed_id = offense_id
            logger.info(f"Saved checkpoint: Last processed offense ID: {offense_id}")
        except Exception as e:
            logger.error(f"Error saving checkpoint: {str(e)}")

    def should_process(self, offense_id):
        """Determine if an offense should be processed based on checkpoint."""
        if self.last_processed_id is None:
            return True
        return offense_id > self.last_processed_id

class RetryableError(Exception):
    """Exception raised for errors that should trigger a retry."""
    pass

class PermanentError(Exception):
    """Exception raised for errors that should not be retried."""
    pass

# === SSL FUNCTIONS ===
def create_ssl_context():
    """
    Create a custom SSL context with configurable security levels.
    
    Security levels:
    - high: Uses TLS 1.2+ with strongest ciphers (default)
    - medium: Uses TLS 1.2 with balanced ciphers
    - low: Allows older protocols and weaker ciphers (not recommended)
    
    Returns:
        SSLContext: Configured SSL context
    
    Raises:
        FileNotFoundError: If certificate file is specified but not found
        Exception: For other SSL configuration errors
    """
    try:
        context = create_urllib3_context()
        
        if SSL_SECURITY_LEVEL == "low":
            # Low security - allow weaker keys and older protocols
            logger.warning("Using low SSL security level - not recommended for production")
            context.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
            context.options |= 0x80000  # OP_NO_TLSv1_3
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.set_ciphers('DEFAULT@SECLEVEL=1')
        elif SSL_SECURITY_LEVEL == "medium":
            # Medium security - allow some older protocols but maintain strong ciphers
            logger.info("Using medium SSL security level")
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('DEFAULT@SECLEVEL=2')
        else:
            # High security (default) - use strongest available settings
            logger.info("Using high SSL security level")
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('DEFAULT@SECLEVEL=3')
        
        if SSL_VERIFY and SSL_CERT_PATH:
            if not os.path.exists(SSL_CERT_PATH):
                logger.error(f"Certificate file not found: {SSL_CERT_PATH}")
                raise FileNotFoundError(f"Certificate file not found: {SSL_CERT_PATH}")
            
            # Load the certificate
            context.load_verify_locations(cafile=SSL_CERT_PATH)
            logger.info(f"Using custom certificate bundle: {SSL_CERT_PATH}")
        elif SSL_VERIFY:
            logger.info("Using system certificate store")
        else:
            logger.warning("SSL verification is disabled. This is not recommended for production use.")
        
        return context
    except Exception as e:
        logger.error(f"Error creating SSL context: {str(e)}")
        logger.error(traceback.format_exc())
        raise

# === API FUNCTIONS ===
def make_request_with_retry(session, method, url, auth=None, headers=None, **kwargs):
    """
    Make an HTTP request with retry logic and exponential backoff.
    
    Args:
        session: Requests session object
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        auth: Authentication tuple (username, token) or None
        headers: Request headers or None
        **kwargs: Additional arguments for requests
        
    Returns:
        Response object
        
    Raises:
        RetryableError: If all retries fail
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = session.request(
                method, 
                url, 
                auth=auth,
                headers=headers,
                timeout=kwargs.pop("timeout", 60),
                **kwargs
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Request failed (attempt {attempt + 1}/{MAX_RETRIES}): {str(e)}")
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Request failed after {MAX_RETRIES} attempts: {str(e)}")
                raise RetryableError(f"Request failed after {MAX_RETRIES} attempts: {str(e)}")

def get_qradar_offenses(session, url, token):
    """
    Fetch offenses from QRadar with error handling.
    
    Args:
        session: Requests session object
        url: QRadar API URL
        token: QRadar API token (SEC token)
        
    Returns:
        List of offenses
        
    Raises:
        RetryableError: For temporary failures
        PermanentError: For permanent failures
    """
    try:
        # Ensure proper QRadar SEC token header
        headers = {
            'SEC': token,  # QRadar SEC token header
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # Log the request (without sensitive data)
        logger.debug(f"Making QRadar request to: {url}")
        logger.debug("Using SEC token authentication")
        
        response = make_request_with_retry(
            session, 
            'GET', 
            url, 
            headers=headers
        )
        
        # Log response status
        logger.debug(f"QRadar response status: {response.status_code}")
        
        return response.json()
    except RetryableError:
        raise
    except Exception as e:
        logger.error(f"Error fetching QRadar offenses: {str(e)}")
        logger.error(traceback.format_exc())
        raise PermanentError(f"Error fetching QRadar offenses: {str(e)}")

def jira_issue_exists(session, url, username, token, project_key, offense_id):
    """
    Check if a Jira issue already exists for the given offense ID.
    
    This function uses the qradar_id custom field to prevent duplicate tickets.
    The JQL query searches for existing issues with the same QRadar offense ID.
    
    Args:
        session: Requests session object
        url: Jira API URL
        username: Jira username
        token: Jira API token
        project_key: Jira project key
        offense_id: QRadar offense ID to check
        
    Returns:
        bool: True if issue exists, False otherwise
    """
    jql = (
        f'project = "{project_key}" AND ('
        f'"qradar_offense_id[Short text]" ~ "{offense_id}" OR '
        f'summary ~ "{offense_id}" OR '
        f'description ~ "{offense_id}"'
        f')'
    )
    search_url = f"{url}/rest/api/2/search"
    headers = {"Accept": "application/json"}
    params = {
        "jql": jql,
        "fields": f"key,summary,status,{JIRA_FIELDS['custom_fields']['qradar_id']}"
    }

    try:
        response = make_request_with_retry(
            session,
            'GET',
            search_url,
            auth=(username, token),
            headers=headers,
            params=params
        )
        issues = response.json().get("issues", [])

        if issues:
            logger.info(f"Found existing Jira issue(s) for offense {offense_id}:")
            for issue in issues:
                key = issue["key"]
                status = issue["fields"]["status"]["name"]
                qid = issue["fields"].get(JIRA_FIELDS['custom_fields']['qradar_id'], "Not set")
                logger.info(f"  - {key}: {issue['fields']['summary']} (Status: {status}, QR ID: {qid})")
                add_duplicate_comment(session, url, username, token, key, offense_id)
            return True

        logger.info(f"No existing issues found for offense {offense_id}")
        return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Jira search error for offense {offense_id}: {e}")
        return False

def add_duplicate_comment(session, url, username, token, issue_key, duplicate_offense_id):
    """
    Add a comment to a Jira issue indicating it's a duplicate.
    
    Args:
        session: Requests session object
        url: Jira API URL
        username: Jira username
        token: Jira API token
        issue_key: Jira issue key
        duplicate_offense_id: QRadar offense ID that was detected as duplicate
    """
    comment_url = f"{url}/rest/api/2/issue/{issue_key}/comment"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    comment = (
        f"Duplicate QRadar offense detected.\n"
        f"* Original QRadar Offense ID: {duplicate_offense_id}\n"
        f"* Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"* This issue was automatically marked as a duplicate to prevent duplicate ticket creation."
    )
    
    payload = {
        "body": comment
    }
    
    try:
        response = make_request_with_retry(
            session,
            'POST',
            comment_url,
            auth=(username, token),
            headers=headers,
            json=payload
        )
        logger.info(f"Added duplicate comment to issue {issue_key}")
        return True
    except Exception as e:
        logger.error(f"Failed to add duplicate comment to issue {issue_key}: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def create_jira_issue(session, url, username, token, project_key, summary, description, priority, offense_id):
    """
    Create a Jira issue with error handling.
    
    Args:
        session: Requests session object
        url: Jira API URL
        username: Jira username
        token: Jira API token
        project_key: Jira project key
        summary: Issue summary
        description: Issue description
        priority: Issue priority
        offense_id: QRadar offense ID
        
    Returns:
        Created issue data
        
    Raises:
        RetryableError: For temporary failures
        PermanentError: For permanent failures
    """
    try:
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        data = {
            'fields': {
                'project': {'key': project_key},
                'summary': summary,
                'description': description,
                'priority': {'name': priority},
                'labels': ["API"],
                JIRA_FIELDS['custom_fields']['qradar_id']: str(offense_id)  # Critical: Set QRadar offense ID
            }
        }
        
        response = make_request_with_retry(
            session,
            'POST',
            f"{url}/rest/api/2/issue",
            auth=(username, token),
            headers=headers,
            json=data
        )
        return response.json()
    except RetryableError:
        raise
    except Exception as e:
        logger.error(f"Error creating Jira issue: {str(e)}")
        logger.error(traceback.format_exc())
        raise PermanentError(f"Error creating Jira issue: {str(e)}")

# === MAIN FUNCTION ===
def main():
    """
    Main function that orchestrates the integration process.
    
    Steps:
    1. Load and validate configuration
    2. Set up SSL context
    3. Fetch offenses from QRadar
    4. Process each offense
    5. Create Jira issues
    6. Handle errors and retries
    
    The function includes comprehensive error handling and logging
    to ensure reliable operation and easy troubleshooting.
    """
    try:
        # Load environment variables
        qradar_url = os.getenv("QRADAR_URL")
        qradar_token = os.getenv("QRADAR_TOKEN")
        jira_url = os.getenv("JIRA_URL")
        jira_username = os.getenv("JIRA_USERNAME")
        jira_token = os.getenv("JIRA_API_TOKEN")
        project_key = os.getenv("PROJECT_KEY")
        test_mode = os.getenv("TEST_MODE", "false").lower() in ("1", "true", "yes")

        # Validate required environment variables
        required_vars = {
            "QRADAR_URL": qradar_url,
            "QRADAR_TOKEN": qradar_token,
            "JIRA_URL": jira_url,
            "JIRA_USERNAME": jira_username,
            "JIRA_API_TOKEN": jira_token,
            "PROJECT_KEY": project_key
        }

        missing_vars = [var for var, value in required_vars.items() if not value]
        if missing_vars:
            raise PermanentError(f"Missing required environment variables: {', '.join(missing_vars)}")

        # Initialize checkpoint manager
        checkpoint_manager = CheckpointManager(CHECKPOINT_FILE)

        # Create a custom session with proper SSL verification
        session = requests.Session()
        if SSL_VERIFY and SSL_CERT_PATH:
            try:
                session.verify = SSL_CERT_PATH
                # Test the certificate with the configured security level
                test_response = session.get("https://www.google.com", timeout=5)
                logger.info("SSL certificate verification test successful")
            except requests.exceptions.SSLError as e:
                if SSL_SECURITY_LEVEL == "low":
                    logger.warning(f"SSL certificate verification warning: {str(e)}")
                    logger.warning("Proceeding with connection despite weak certificate")
                else:
                    logger.error(f"SSL certificate verification failed: {str(e)}")
                    logger.error("Please check your certificate configuration or set SSL_SECURITY_LEVEL=low if needed")
                    raise
            except Exception as e:
                logger.error(f"Error testing SSL configuration: {str(e)}")
                raise
        elif SSL_VERIFY:
            # No custom CA bundle provided: verify against the system trust store
            # instead of silently disabling verification.
            session.verify = True
            logger.info("Using system CA trust store for SSL verification")
        else:
            session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification is disabled. This is not recommended for production use.")

        # Fetch offenses from QRadar
        logger.info("Fetching offenses from QRadar...")
        offenses = get_qradar_offenses(session, qradar_url, qradar_token)
        
        if not offenses:
            logger.info("No offenses found in QRadar")
            return

        # Process each offense
        for offense in offenses:
            try:
                offense_id = offense.get('id')
                
                # Skip if already processed
                if not checkpoint_manager.should_process(offense_id):
                    logger.info(f"Skipping already processed offense ID: {offense_id}")
                    continue
                
                # Check if issue already exists
                if jira_issue_exists(session, jira_url, jira_username, jira_token, project_key, offense_id):
                    logger.info(f"Skipping offense {offense_id} - already exists in Jira")
                    continue
                
                # Map QRadar severity to Jira priority
                severity = offense.get('severity', 0)
                if severity >= 7:
                    priority = "Highest"
                elif severity >= 5:
                    priority = "High"
                elif severity >= 3:
                    priority = "Medium"
                else:
                    priority = "Low"

                # Create Jira issue
                summary = f"QRadar Offense {offense_id}: {offense.get('description', 'No description')}"
                description = f"""
                QRadar Offense Details:
                - ID: {offense_id}
                - Description: {offense.get('description', 'No description')}
                - Severity: {severity}
                - Status: {offense.get('status', 'Unknown')}
                - Start Time: {offense.get('start_time', 'Unknown')}
                - Source IP: {offense.get('source_ip', 'Unknown')}
                - Destination IP: {offense.get('destination_ip', 'Unknown')}
                """

                if not test_mode:
                    logger.info(f"Creating Jira issue for offense ID: {offense_id}")
                    jira_response = create_jira_issue(
                        session,
                        jira_url,
                        jira_username,
                        jira_token,
                        project_key,
                        summary,
                        description,
                        priority,
                        offense_id
                    )
                    logger.info(f"Created Jira issue: {jira_response.get('key')}")
                else:
                    logger.info(f"[TEST MODE] Would create Jira issue for offense ID: {offense_id}")
                    logger.info(f"Summary: {summary}")
                    logger.info(f"Priority: {priority}")

                # Save checkpoint after successful processing
                checkpoint_manager.save_checkpoint(offense_id)

            except RetryableError:
                logger.error(f"Failed to process offense ID {offense_id} after retries. Skipping...")
                continue
            except PermanentError:
                logger.error(f"Permanent error processing offense ID {offense_id}. Skipping...")
                continue
            except Exception as e:
                logger.error(f"Unexpected error processing offense ID {offense_id}: {str(e)}")
                logger.error(traceback.format_exc())
                continue

    except Exception as e:
        logger.error(f"Script failed: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 