import json
import os
import unittest
from unittest.mock import patch, MagicMock

# Import the Lambda handler function (adjust path if necessary)
# Assuming src is in PYTHONPATH or tests are run from root
from src import oauth_callback

class TestOAuthCallbackHandler(unittest.TestCase):

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth'
    })
    @patch('src.oauth_callback.secrets_manager')
    @patch('src.oauth_callback.dynamodb')
    @patch('src.oauth_callback.requests')
    def test_handler_success(self, mock_requests, mock_dynamodb, mock_secrets_manager):
        # --- Mocks Setup ---
        # Secrets Manager
        mock_secrets_manager.get_secret_value.return_value = {
            'SecretString': json.dumps({
                'GOOGLE_CLIENT_ID': 'test_client_id',
                'GOOGLE_CLIENT_SECRET': 'test_client_secret'
            })
        }

        # Google OAuth Token Exchange (requests.post)
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token' # often present
        }
        # Google UserInfo (requests.get)
        mock_userinfo_response = MagicMock()
        mock_userinfo_response.status_code = 200
        mock_userinfo_response.json.return_value = {
            'sub': 'test_google_user_id_123',
            'email': 'test@example.com'
        }
        # Assign responses to mock_requests calls
        mock_requests.post.return_value = mock_token_response
        mock_requests.get.return_value = mock_userinfo_response

        # DynamoDB
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        # --- Lambda Event ---
        event = {
            "queryStringParameters": {
                "code": "sample_auth_code"
            },
            "headers": {
                "host": "api.example.com",
                "x-forwarded-proto": "https"
            },
            "requestContext": {
                "path": "/Prod/oauth2callback", # Path with stage
                "stage": "Prod"
            },
            "path": "/oauth2callback" # Resource path
        }

        # --- Call Handler ---
        response = oauth_callback.handler(event, None)

        # --- Assertions ---
        self.assertEqual(response['statusCode'], 200)
        self.assertIn("Authorization Successful!", response['body'])
        self.assertEqual(response['headers']['Content-Type'], 'text/html')

        # Verify Secrets Manager call
        mock_secrets_manager.get_secret_value.assert_called_once_with(SecretId='test/gmail/oauth')

        # Verify Google token exchange call
        expected_redirect_uri = "https://api.example.com/Prod/oauth2callback"
        mock_requests.post.assert_called_once_with(
            oauth_callback.GOOGLE_TOKEN_URL,
            data={
                'code': 'sample_auth_code',
                'client_id': 'test_client_id',
                'client_secret': 'test_client_secret',
                'redirect_uri': expected_redirect_uri,
                'grant_type': 'authorization_code'
            }
        )
        mock_token_response.raise_for_status.assert_called_once()

        # Verify Google userinfo call
        mock_requests.get.assert_called_once_with(
            oauth_callback.GOOGLE_USERINFO_URL,
            headers={'Authorization': 'Bearer test_access_token'}
        )
        mock_userinfo_response.raise_for_status.assert_called_once()

        # Verify DynamoDB put_item call
        mock_dynamodb.Table.assert_called_once_with('TestUserTokensTable')
        mock_table.put_item.assert_called_once_with(
            Item={
                'userId': 'test_google_user_id_123',
                'refreshToken': 'test_refresh_token'
            }
        )

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth'
    })
    def test_handler_missing_code(self,):
        event = {
            "queryStringParameters": {}, # No code
             "headers": {
                "host": "api.example.com",
                "x-forwarded-proto": "https"
            },
            "requestContext": {
                "path": "/Prod/oauth2callback",
                "stage": "Prod"
            },
            "path": "/oauth2callback"
        }
        response = oauth_callback.handler(event, None)
        self.assertEqual(response['statusCode'], 400)
        self.assertIn("Authorization code is missing", response['body'])

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth'
    })
    def test_handler_google_error_param(self,):
        event = {
            "queryStringParameters": {
                "error": "access_denied"
            },
             "headers": { # Still need headers for redirect_uri build attempt, though it might not get that far
                "host": "api.example.com",
                "x-forwarded-proto": "https"
            },
            "requestContext": {
                "path": "/Prod/oauth2callback",
                "stage": "Prod"
            },
             "path": "/oauth2callback"
        }
        response = oauth_callback.handler(event, None)
        self.assertEqual(response['statusCode'], 400)
        self.assertIn("OAuth Error", response['body'])
        self.assertIn("access_denied", response['body'])

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth'
    })
    @patch('src.oauth_callback.secrets_manager')
    @patch('src.oauth_callback.requests.post') # Only mock post for this test
    def test_handler_token_exchange_fails(self, mock_post, mock_secrets_manager):
        mock_secrets_manager.get_secret_value.return_value = {
            'SecretString': json.dumps({
                'GOOGLE_CLIENT_ID': 'test_client_id',
                'GOOGLE_CLIENT_SECRET': 'test_client_secret'
            })
        }
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = oauth_callback.requests.exceptions.HTTPError("Token exchange failed")
        mock_response.text = "Google error details"
        mock_post.return_value = mock_response

        event = {
            "queryStringParameters": {"code": "sample_auth_code"},
            "headers": {"host": "api.example.com", "x-forwarded-proto": "https"},
            "requestContext": {"path": "/Prod/oauth2callback", "stage": "Prod"},
            "path": "/oauth2callback"
        }
        response = oauth_callback.handler(event, None)
        self.assertEqual(response['statusCode'], 500) # Or whatever error code exchange_code_for_tokens translates to
        self.assertIn("Server Error", response['body']) # Check for generic error message

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth'
    })
    @patch('src.oauth_callback.secrets_manager')
    @patch('src.oauth_callback.requests')
    def test_handler_no_refresh_token(self, mock_requests, mock_secrets_manager):
        mock_secrets_manager.get_secret_value.return_value = {
            'SecretString': json.dumps({'GOOGLE_CLIENT_ID': 'id', 'GOOGLE_CLIENT_SECRET': 'secret'})}

        mock_token_response = MagicMock()
        mock_token_response.json.return_value = {'access_token': 'acc_token'} # No refresh_token
        mock_requests.post.return_value = mock_token_response

        event = {
            "queryStringParameters": {"code": "sample_auth_code"},
            "headers": {"host": "api.example.com", "x-forwarded-proto": "https"},
            "requestContext": {"path": "/Prod/oauth2callback", "stage": "Prod"},
            "path": "/oauth2callback"
        }
        response = oauth_callback.handler(event, None)
        self.assertEqual(response['statusCode'], 400) # As per current handler logic
        self.assertIn("Refresh token not received", response['body'])

    @patch.dict(os.environ, {}) # Missing env vars
    def test_handler_missing_env_vars(self):
        event = {"queryStringParameters": {"code": "sample_auth_code"}}
        response = oauth_callback.handler(event, None)
        self.assertEqual(response['statusCode'], 500)
        self.assertIn("Server configuration error", json.loads(response['body'])['error'])

    def test_build_redirect_uri(self):
        # Test cases for build_redirect_uri
        # Case 1: Standard with stage in requestContext.path
        event1 = {
            "headers": {"host": "xyz.execute-api.us-east-1.amazonaws.com", "x-forwarded-proto": "https"},
            "requestContext": {"path": "/Prod/oauth2callback", "stage": "Prod"}, # Path includes stage
            "path": "/oauth2callback" # Resource path
        }
        self.assertEqual(oauth_callback.build_redirect_uri(event1), "https://xyz.execute-api.us-east-1.amazonaws.com/Prod/oauth2callback")

        # Case 2: Stage not in requestContext.path, but present in requestContext.stage
        event2 = {
            "headers": {"host": "abc.execute-api.us-west-2.amazonaws.com", "x-forwarded-proto": "https"},
            "requestContext": {"path": "/oauth2callback", "stage": "Dev"}, # Path does NOT include stage
            "path": "/oauth2callback" # Resource path
        }
        self.assertEqual(oauth_callback.build_redirect_uri(event2), "https://abc.execute-api.us-west-2.amazonaws.com/Dev/oauth2callback")

        # Case 3: No stage (e.g. custom domain, stage might be empty or root)
        event3 = {
            "headers": {"host": "auth.mydomain.com", "x-forwarded-proto": "https"},
            "requestContext": {"path": "/oauth2callback", "stage": "$default"}, # or None, or some other non-Prod/Dev value
            "path": "/oauth2callback"
        }
        # If stage is '$default' or similar, it usually means it's not part of the path.
        # The logic `if stage and not path.startswith(f"/{stage}")` handles this.
        # If stage is considered "$default", it won't be prepended.
        self.assertEqual(oauth_callback.build_redirect_uri(event3), "https://auth.mydomain.com/oauth2callback")

        # Case 4: Path from event itself (e.g. if requestContext.path is not reliable)
        event4 = {
            "headers": {"host": "123.execute-api.eu-central-1.amazonaws.com", "x-forwarded-proto": "https"},
            "requestContext": {"stage": "Test"}, # Stage is Test
            "path": "/Test/oauth2callback" # Path already includes stage
        }
        self.assertEqual(oauth_callback.build_redirect_uri(event4), "https://123.execute-api.eu-central-1.amazonaws.com/Test/oauth2callback")

        # Case 5: Missing host header
        event5 = {
            "headers": {"x-forwarded-proto": "https"}, # No host
            "requestContext": {"path": "/Prod/oauth2callback", "stage": "Prod"},
            "path": "/oauth2callback"
        }
        with self.assertRaises(ValueError) as context:
            oauth_callback.build_redirect_uri(event5)
        self.assertTrue("Host header missing" in str(context.exception))


if __name__ == '__main__':
    unittest.main()
