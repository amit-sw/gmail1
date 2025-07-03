import json
import os
import logging
import datetime
import boto3
import requests # For making HTTP requests to Google

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
secrets_manager = boto3.client('secretsmanager')
dynamodb = boto3.resource('dynamodb')

# Environment variables
DYNAMO_TABLE_NAME = os.environ.get('DYNAMO_TABLE_NAME')
SECRETS_MANAGER_SECRET_NAME = os.environ.get('SECRETS_MANAGER_SECRET_NAME')
MAX_USERS_PER_INVOCATION = int(os.environ.get('MAX_USERS_PER_INVOCATION', '10')) # Default to 10

# Google OAuth settings
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
# Gmail API settings
GMAIL_API_BASE_URL = "https://www.googleapis.com/gmail/v1/users"

def get_google_oauth_credentials():
    """Retrieves Google OAuth client ID and secret from AWS Secrets Manager."""
    try:
        response = secrets_manager.get_secret_value(SecretId=SECRETS_MANAGER_SECRET_NAME)
        secret = json.loads(response['SecretString'])
        return secret['GOOGLE_CLIENT_ID'], secret['GOOGLE_CLIENT_SECRET']
    except Exception as e:
        logger.error(f"Error retrieving Google OAuth credentials from Secrets Manager: {e}")
        raise

def refresh_access_token(refresh_token, client_id, client_secret):
    """Refreshes Google access token using the refresh token."""
    payload = {
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'refresh_token'
    }
    try:
        response = requests.post(GOOGLE_TOKEN_URL, data=payload)
        response.raise_for_status()
        token_data = response.json()
        if 'access_token' not in token_data:
            logger.error("Access token not found in refresh response.")
            # This could indicate the refresh token is invalid or revoked.
            raise ValueError("Access token missing from refresh response.")
        return token_data['access_token']
    except requests.exceptions.RequestException as e:
        logger.error(f"Error refreshing access token: {e}")
        if e.response is not None:
            logger.error(f"Google token refresh API response: {e.response.text}")
            # Check for specific errors like 'invalid_grant'
            if e.response.status_code == 400 or e.response.status_code == 401: # Bad Request or Unauthorized
                try:
                    error_details = e.response.json()
                    if error_details.get("error") == "invalid_grant":
                        logger.warning("Refresh token is invalid or revoked (invalid_grant).")
                        raise InvalidGrantError("Refresh token is invalid (invalid_grant).")
                except json.JSONDecodeError:
                    pass # Fall through to generic error
        raise # Re-raise the original or InvalidGrantError

class InvalidGrantError(Exception):
    """Custom exception for invalid_grant errors from Google OAuth."""
    pass

def get_users_from_dynamodb(limit):
    """Scans DynamoDB for user records."""
    if not DYNAMO_TABLE_NAME:
        logger.error("DynamoDB table name not configured.")
        raise ValueError("DynamoDB table name not configured.")

    table = dynamodb.Table(DYNAMO_TABLE_NAME)
    users = []
    try:
        # Scan operation can be expensive. For production, consider GSI or more targeted queries if possible.
        # The design doc mentions "Scan", so implementing that.
        response = table.scan(Limit=limit)
        users.extend(response.get('Items', []))

        # Paginate if necessary, though for MAX_USERS_PER_INVOCATION, one scan might be enough
        while 'LastEvaluatedKey' in response and len(users) < limit:
            logger.info(f"Scanning DynamoDB for more users, current count: {len(users)}")
            response = table.scan(Limit=limit - len(users), ExclusiveStartKey=response['LastEvaluatedKey'])
            users.extend(response.get('Items', []))

        logger.info(f"Fetched {len(users)} users from DynamoDB.")
        return users
    except Exception as e:
        logger.error(f"Error scanning DynamoDB for users: {e}")
        raise

def fetch_unread_emails(user_id_for_api, access_token, last_fetched_at_iso=None):
    """Fetches unread email message IDs from Gmail API."""
    headers = {'Authorization': f'Bearer {access_token}'}
    query = "is:unread"
    if last_fetched_at_iso:
        # Gmail API's 'after' q parameter expects a Unix timestamp (seconds)
        # Convert ISO 8601 string to datetime object, then to timestamp
        try:
            dt_object = datetime.datetime.fromisoformat(last_fetched_at_iso.replace('Z', '+00:00'))
            timestamp_seconds = int(dt_object.timestamp())
            query += f" after:{timestamp_seconds}"
        except ValueError as ve:
            logger.warning(f"Invalid lastFetchedAt format '{last_fetched_at_iso}', cannot use for query: {ve}")

    params = {'q': query, 'maxResults': 20} # Limit results per call for now
    url = f"{GMAIL_API_BASE_URL}/{user_id_for_api}/messages"

    message_ids = []
    page_token = None
    try:
        while True:
            if page_token:
                params['pageToken'] = page_token

            logger.info(f"Fetching messages for user '{user_id_for_api}' with query: '{query}', params: {params}")
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            if 'messages' in data:
                message_ids.extend([msg['id'] for msg in data['messages']])

            page_token = data.get('nextPageToken')
            if not page_token or len(message_ids) >= params['maxResults']: # Stop if no more pages or limit hit
                break

        logger.info(f"Found {len(message_ids)} unread messages for user '{user_id_for_api}'.")
        return message_ids
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching unread emails for user '{user_id_for_api}': {e}")
        if e.response is not None: logger.error(f"Gmail API response: {e.response.text}")
        raise

def get_email_details(user_id_for_api, message_id, access_token):
    """Fetches details for a specific email message."""
    headers = {'Authorization': f'Bearer {access_token}'}
    url = f"{GMAIL_API_BASE_URL}/{user_id_for_api}/messages/{message_id}?format=metadata&metadataHeaders=Subject" # Only fetch Subject for now
    try:
        logger.info(f"Fetching details for messageId '{message_id}' for user '{user_id_for_api}'.")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching email details for messageId '{message_id}', user '{user_id_for_api}': {e}")
        if e.response is not None: logger.error(f"Gmail API response: {e.response.text}")
        raise

def update_user_in_dynamodb(user_id, updates):
    """Updates user record in DynamoDB. Can set lastFetchedAt or needsReauth."""
    if not DYNAMO_TABLE_NAME:
        logger.error("DynamoDB table name not configured for update.")
        return

    table = dynamodb.Table(DYNAMO_TABLE_NAME)
    expression_attribute_values = {}
    update_expression_parts = []

    if 'lastFetchedAt' in updates:
        expression_attribute_values[':lfa'] = updates['lastFetchedAt']
        update_expression_parts.append("lastFetchedAt = :lfa")

    if 'needsReauth' in updates:
        expression_attribute_values[':nr'] = updates['needsReauth']
        update_expression_parts.append("needsReauth = :nr")

    if not update_expression_parts:
        logger.info(f"No updates specified for user {user_id}.")
        return

    update_expression = "SET " + ", ".join(update_expression_parts)

    try:
        table.update_item(
            Key={'userId': user_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values
        )
        logger.info(f"Successfully updated user {user_id} in DynamoDB with: {updates}")
    except Exception as e:
        logger.error(f"Error updating user {user_id} in DynamoDB: {e}")
        # Don't re-raise, allow other users to be processed.

def process_user(user_record, client_id, client_secret):
    """Processes a single user: refresh token, fetch emails, update DynamoDB."""
    user_id = user_record.get('userId')
    refresh_token = user_record.get('refreshToken')
    last_fetched_at = user_record.get('lastFetchedAt') # This is an ISO 8601 string from DynamoDB

    if not user_id or not refresh_token:
        logger.warning(f"Skipping user record due to missing userId or refreshToken: {user_record}")
        return

    logger.info(f"Processing user: {user_id}")
    current_time_iso = datetime.datetime.utcnow().isoformat() + "Z"

    try:
        access_token = refresh_access_token(refresh_token, client_id, client_secret)

        # In Gmail API, 'me' can be used as user_id if you have the user's access token
        user_id_for_api = 'me'

        message_ids = fetch_unread_emails(user_id_for_api, access_token, last_fetched_at)

        if message_ids:
            logger.info(f"User {user_id}: Found {len(message_ids)} new messages.")
            for msg_id in message_ids:
                email_data = get_email_details(user_id_for_api, msg_id, access_token)
                subject = "No Subject"
                if email_data and 'payload' in email_data and 'headers' in email_data['payload']:
                    for header in email_data['payload']['headers']:
                        if header['name'].lower() == 'subject':
                            subject = header['value']
                            break
                logger.info(f"User {user_id}, Message ID {msg_id}: Subject: '{subject}'")
                # Placeholder for further processing (e.g., send to SNS/SQS)
        else:
            logger.info(f"User {user_id}: No new unread messages found since last fetch.")

        # Update lastFetchedAt, and clear needsReauth if it was set
        update_user_in_dynamodb(user_id, {'lastFetchedAt': current_time_iso, 'needsReauth': False})

    except InvalidGrantError:
        logger.warning(f"User {user_id} needs re-authentication (invalid_grant). Flagging in DynamoDB.")
        update_user_in_dynamodb(user_id, {'needsReauth': True, 'lastFetchedAt': current_time_iso}) # Update LFA too
    except Exception as e:
        logger.error(f"Failed to process user {user_id}: {e}", exc_info=True)
        # Optionally, update lastFetchedAt even on general failure to avoid reprocessing immediately,
        # or leave it to retry the same messages next time. For now, only updating on success or invalid_grant.


def handler(event, context):
    logger.info(f"EmailFetcherJob triggered. Event: {json.dumps(event)}")

    if not DYNAMO_TABLE_NAME or not SECRETS_MANAGER_SECRET_NAME:
        logger.error("Environment variables DYNAMO_TABLE_NAME or SECRETS_MANAGER_SECRET_NAME not set.")
        return {'statusCode': 500, 'body': json.dumps({'error': 'Server configuration error.'})}

    try:
        client_id, client_secret = get_google_oauth_credentials()
        users_to_process = get_users_from_dynamodb(MAX_USERS_PER_INVOCATION)

        if not users_to_process:
            logger.info("No users found to process.")
            return {'statusCode': 200, 'body': json.dumps({'message': 'No users to process.'})}

        processed_count = 0
        failed_count = 0
        for user_record in users_to_process:
            try:
                process_user(user_record, client_id, client_secret)
                processed_count +=1
            except Exception as e: # Catch exceptions from process_user to allow loop to continue
                logger.error(f"Unhandled error during processing for a user (see logs above): {e}")
                failed_count +=1

        logger.info(f"EmailFetcherJob finished. Processed: {processed_count}, Failed attempts: {failed_count}")
        return {
            'statusCode': 200,
            'body': json.dumps({'message': f'Job finished. Processed: {processed_count}, Failed: {failed_count}'})
        }

    except Exception as e:
        logger.error(f"Unhandled exception in EmailFetcherJob handler: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Critical error in EmailFetcherJob.'})
        }

# Example usage (for local testing if needed)
if __name__ == '__main__':
    # Mock event and context
    # Requires environment variables like DYNAMO_TABLE_NAME, SECRETS_MANAGER_SECRET_NAME
    # os.environ['DYNAMO_TABLE_NAME'] = 'UserTokens'
    # os.environ['SECRETS_MANAGER_SECRET_NAME'] = 'gmail/oauth'
    # os.environ['MAX_USERS_PER_INVOCATION'] = '5'
    # handler({}, None)
    pass
