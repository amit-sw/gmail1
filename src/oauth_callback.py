import json
import os
import logging
import urllib.parse
import boto3
import requests # For making HTTP requests to Google

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients (initialized globally for potential reuse)
secrets_manager = boto3.client('secretsmanager')
dynamodb = boto3.resource('dynamodb')

# Environment variables
DYNAMO_TABLE_NAME = os.environ.get('DYNAMO_TABLE_NAME')
SECRETS_MANAGER_SECRET_NAME = os.environ.get('SECRETS_MANAGER_SECRET_NAME')

# Google OAuth settings - these will be fetched from Secrets Manager
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo" # To get user's Google ID (sub)
GMAIL_PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"

def get_google_oauth_credentials():
    """Retrieves Google OAuth client ID and secret from AWS Secrets Manager."""
    try:
        response = secrets_manager.get_secret_value(SecretId=SECRETS_MANAGER_SECRET_NAME)
        secret = json.loads(response['SecretString'])
        return secret['GOOGLE_CLIENT_ID'], secret['GOOGLE_CLIENT_SECRET']
    except Exception as e:
        logger.error(f"Error retrieving Google OAuth credentials from Secrets Manager: {e}")
        raise

def exchange_code_for_tokens(code, client_id, client_secret, redirect_uri):
    """Exchanges authorization code for access and refresh tokens."""
    payload = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    try:
        response = requests.post(GOOGLE_TOKEN_URL, data=payload)
        response.raise_for_status() # Raises an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error exchanging code for tokens: {e}")
        if e.response is not None:
            logger.error(f"Google token API response: {e.response.text}")
        raise

def get_user_google_id(access_token):
    """Fetches the user's email address from Gmail profile using the access token."""
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        response = requests.get(GMAIL_PROFILE_URL, headers=headers)
        response.raise_for_status()
        profile = response.json()
        if 'emailAddress' not in profile:
            raise ValueError("Email address not found in Gmail profile response.")
        return profile['emailAddress']
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching Gmail profile: {e}")
        if e.response is not None:
            logger.error(f"Gmail profile API response: {e.response.text}")
        raise
    except ValueError as e:
        logger.error(f"Error processing Gmail profile response: {e}")
        raise


def store_token_in_dynamodb(user_id, refresh_token):
    """Stores the refresh token in DynamoDB."""
    if not DYNAMO_TABLE_NAME:
        logger.error("DynamoDB table name not configured.")
        raise ValueError("DynamoDB table name not configured.")

    table = dynamodb.Table(DYNAMO_TABLE_NAME)
    try:
        table.put_item(
            Item={
                'userId': user_id,
                'refreshToken': refresh_token,
                # 'lastFetchedAt': None # Initially not set, or set to a default past date
            }
        )
        logger.info(f"Successfully stored refresh token for userId: {user_id}")
    except Exception as e:
        logger.error(f"Error storing token in DynamoDB for userId {user_id}: {e}")
        raise

def build_redirect_uri(event):
    """
    Constructs the redirect URI dynamically at runtime based on the API Gateway event.
    This must match exactly what Google expects.
    """
    headers = event.get('headers', {})
    request_context = event.get('requestContext', {})

    # Scheme (http or https)
    scheme = headers.get('x-forwarded-proto', 'https')

    # Host (API Gateway domain name)
    #host = headers.get('host')
    host = headers.get('Host') or headers.get('host')
    if not host:
        logger.error(f"Host header missing, cannot construct redirect_uri: {headers=}")
        raise ValueError("Host header missing")

    # Path (API Gateway stage and path)
    # path = request_context.get('path', '/oauth2callback') # This might include the stage
    # For a non-proxy integration, the path is fixed by API Gateway configuration.
    # For proxy, it's in event['path']. Assuming it's /oauth2callback as per template.
    path = event.get('path')
    if not path: # Fallback if path is not in event directly
        path = request_context.get('path')
        if not path: # If path is still not found, default to what's in template
            logger.warning("Path not found in event or requestContext, defaulting to /oauth2callback.")
            path = "/oauth2callback" # As defined in template.yaml
            # If using a stage, it needs to be prefixed, e.g. /Prod/oauth2callback
            # The SAM template output `OAuthCallbackApiEndpoint` provides the full URL including stage.
            # However, the redirect URI used in the *initial* Google auth request must match *exactly*.
            # If deployed to a stage (e.g., /Prod), that stage needs to be part of the redirect URI.
            # This is tricky because the Lambda doesn't always know its full stage path.
            # The `ServerlessRestApi.execute-api.../Prod/oauth2callback` implies a stage.
            # A common practice is to pass the redirect_uri as a 'state' parameter or configure it
            # statically if the deployment stage is fixed.
            # For now, let's assume the redirect URI registered with Google includes the stage if applicable.
            # The `event['path']` for an API Gateway proxy integration should give the resource path.
            # If the API Gateway endpoint in template.yaml is `.../Prod/oauth2callback`, then `event['path']`
            # should be `/oauth2callback` if it's a root resource, or `/Prod/oauth2callback` if stage is part of path.
            # The design doc's SAM snippet uses `Path: /oauth2callback` directly on the API event.
            # This usually means the stage is part of the domain, not the path passed to Lambda.

    # If API Gateway is configured with a stage, e.g., 'Prod', the `event.path` might be just `/oauth2callback`
    # but the actual redirect URI needs to be `https://domain/Prod/oauth2callback`.
    # The `event.requestContext.stage` can provide the stage.
    stage = request_context.get('stage')

    # If the path from the event already includes the stage, we don't want to add it again.
    # Example: path = /Prod/oauth2callback, stage = Prod. We don't want /Prod/Prod/oauth2callback.
    # A simple check: if path starts with /<stage>/, then use path as is.
    full_path = path
    if stage and not path.startswith(f"/{stage}"):
        full_path = f"/{stage}{path}"

    redirect_uri = f"{scheme}://{host}{full_path}"
    logger.info(f"Constructed redirect_uri: {redirect_uri}")
    return redirect_uri


def handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")

    if not DYNAMO_TABLE_NAME or not SECRETS_MANAGER_SECRET_NAME:
        logger.error("Environment variables DYNAMO_TABLE_NAME or SECRETS_MANAGER_SECRET_NAME not set.")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Server configuration error.'}),
            'headers': {'Content-Type': 'application/json'}
        }

    try:
        query_params = event.get('queryStringParameters', {})
        if not query_params: # For safety, handle cases where it might be None
            query_params = {}

        auth_code = query_params.get('code')
        error = query_params.get('error')

        if error:
            logger.error(f"OAuth error received from Google: {error}")
            return {
                'statusCode': 400,
                'body': f"<html><body><h1>OAuth Error</h1><p>Details: {error}. Please try again or contact support.</p></body></html>",
                'headers': {'Content-Type': 'text/html'}
            }

        if not auth_code:
            logger.error("Authorization code not found in query parameters.")
            return {
                'statusCode': 400,
                'body': "<html><body><h1>Error</h1><p>Authorization code is missing.</p></body></html>",
                'headers': {'Content-Type': 'text/html'}
            }

        # Construct the redirect_uri dynamically. This must match the one
        # registered with Google and used in the initial authorization request.
        # This is crucial for the token exchange to succeed.
        try:
            # This is the redirect URI that this Lambda is currently serving.
            # It must match the redirect_uri used when initiating the OAuth flow with Google.
            current_redirect_uri = build_redirect_uri(event)
        except ValueError as e:
             return {
                'statusCode': 500,
                'body': f"<html><body><h1>Server Error</h1><p>Could not determine redirect URI: {e}.</p></body></html>",
                'headers': {'Content-Type': 'text/html'}
            }


        # Retrieve Google Client ID and Secret
        client_id, client_secret = get_google_oauth_credentials()

        # Exchange code for tokens
        token_data = exchange_code_for_tokens(auth_code, client_id, client_secret, current_redirect_uri)

        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token') # This is key

        if not access_token: # Should not happen if exchange was successful
            logger.error("Access token not found in Google's response.")
            return {
                'statusCode': 500,
                'body': "<html><body><h1>Error</h1><p>Failed to obtain access token from Google.</p></body></html>",
                'headers': {'Content-Type': 'text/html'}
            }

        if not refresh_token:
            # This can happen if the user has already authorized the app and it's not the first time,
            # or if prompt=consent was not used. The design doc specifies prompt=consent.
            logger.warning("Refresh token not found in Google's response. This might be an issue if it's the first authorization for this user or if offline access is strictly needed immediately. Ensure 'prompt=consent' and 'access_type=offline' were used in the auth URL.")
            # For now, we will proceed if we have an access token, but this is a critical piece for long-term access.
            # If a refresh token is absolutely required here, we should error out.
            # The design doc implies refresh token is obtained here.
            return {
                'statusCode': 400, # Or 500, as this is unexpected if prompt=consent is used.
                'body': "<html><body><h1>Error</h1><p>Refresh token not received from Google. Ensure you are granting offline access and this is the first authorization or 'prompt=consent' was used.</p></body></html>",
                'headers': {'Content-Type': 'text/html'}
            }

        # Get user's Google ID (sub) to use as our userId
        user_google_id = get_user_google_id(access_token)

        # Store the refresh token in DynamoDB
        store_token_in_dynamodb(user_google_id, refresh_token)

        # Return success HTML page
        # The user ID is not strictly needed in the success message, but could be logged.
        logger.info(f"Successfully processed OAuth callback for Google user ID: {user_google_id}")
        return {
            'statusCode': 200,
            'body': "<html><body><h1>Authorization Successful!</h1><p>You have successfully authorized the Gmail Assistant. You may now close this window.</p></body></html>",
            'headers': {'Content-Type': 'text/html'}
        }

    except Exception as e:
        logger.error(f"Unhandled exception in OAuthCallbackHandler: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': "<html><body><h1>Server Error</h1><p>An unexpected error occurred. Please try again later.</p></body></html>",
            'headers': {'Content-Type': 'text/html'}
        }

# Example usage (for local testing if needed, though typically tested via SAM local invoke)
if __name__ == '__main__':
    # Mock event and context for local testing
    # This requires setting up environment variables and potentially mocking AWS services
    # Example: os.environ['DYNAMO_TABLE_NAME'] = 'UserTokens'
    # os.environ['SECRETS_MANAGER_SECRET_NAME'] = 'gmail/oauth'
    # mock_event = {
    #     "queryStringParameters": {
    #         "code": "sample_auth_code"
    #     },
    #     "headers": { # Required for build_redirect_uri
    #         "host": "your-api-id.execute-api.region.amazonaws.com",
    #         "x-forwarded-proto": "https"
    #     },
    #     "requestContext": { # Required for build_redirect_uri
    #         "path": "/Prod/oauth2callback", # Or just /oauth2callback if stage is not in path
    #         "stage": "Prod"
    #     },
    #     "path": "/oauth2callback" # Resource path
    # }
    # response = handler(mock_event, None)
    # print(response)
    pass
