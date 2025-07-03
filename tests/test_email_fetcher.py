import json
import os
import unittest
from unittest.mock import patch, MagicMock, call
import datetime

# Import the Lambda handler function
from src import email_fetcher
# from src.email_fetcher import InvalidGrantError # Import custom exception if needed for specific asserts

class TestEmailFetcherJob(unittest.TestCase):

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth',
        'MAX_USERS_PER_INVOCATION': '5'
    })
    @patch('src.email_fetcher.secrets_manager')
    @patch('src.email_fetcher.dynamodb')
    @patch('src.email_fetcher.requests')
    @patch('src.email_fetcher.datetime') # To control 'utcnow'
    def test_handler_success_multiple_users_emails_found(self, mock_datetime, mock_requests, mock_dynamodb, mock_secrets_manager):
        # --- Mocks Setup ---
        # Time
        mock_now = datetime.datetime(2023, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        mock_datetime.datetime.utcnow.return_value = mock_now
        expected_iso_time = "2023-01-01T12:00:00Z"


        # Secrets Manager
        mock_secrets_manager.get_secret_value.return_value = {
            'SecretString': json.dumps({
                'GOOGLE_CLIENT_ID': 'test_client_id',
                'GOOGLE_CLIENT_SECRET': 'test_client_secret'
            })
        }

        # DynamoDB - Scan returns two users
        mock_user1 = {'userId': 'user1', 'refreshToken': 'refresh_token_1', 'lastFetchedAt': '2023-01-01T10:00:00Z'}
        mock_user2 = {'userId': 'user2', 'refreshToken': 'refresh_token_2'} # No lastFetchedAt
        mock_dynamodb.Table.return_value.scan.return_value = {
            'Items': [mock_user1, mock_user2]
        }

        # Google OAuth Token Refresh (requests.post) - successful for both
        mock_refresh_response1 = MagicMock()
        mock_refresh_response1.json.return_value = {'access_token': 'access_token_user1'}
        mock_refresh_response2 = MagicMock()
        mock_refresh_response2.json.return_value = {'access_token': 'access_token_user2'}

        # Gmail API List Messages (requests.get)
        mock_list_emails_response_user1 = MagicMock()
        mock_list_emails_response_user1.json.return_value = {
            'messages': [{'id': 'msg1_user1'}, {'id': 'msg2_user1'}]
        }
        mock_list_emails_response_user2_no_new = MagicMock() # User 2 has no new emails
        mock_list_emails_response_user2_no_new.json.return_value = {}

        # Gmail API Get Message Details (requests.get)
        mock_email_detail_response1_user1 = MagicMock()
        mock_email_detail_response1_user1.json.return_value = {
            'id': 'msg1_user1', 'payload': {'headers': [{'name': 'Subject', 'value': 'Hello User1'}]}
        }
        mock_email_detail_response2_user1 = MagicMock()
        mock_email_detail_response2_user1.json.return_value = {
            'id': 'msg2_user1', 'payload': {'headers': [{'name': 'Subject', 'value': 'Meeting User1'}]}
        }

        # Configure side_effects for requests.post and requests.get based on URL or params
        def requests_post_side_effect(url, data):
            if data['refresh_token'] == 'refresh_token_1': return mock_refresh_response1
            if data['refresh_token'] == 'refresh_token_2': return mock_refresh_response2
            raise ValueError("Unexpected refresh token in POST")

        def requests_get_side_effect(url, headers, params=None):
            # Token refresh calls
            if 'gmail/v1/users/me/messages' in url and headers['Authorization'] == 'Bearer access_token_user1':
                # Check query params for user1 (has lastFetchedAt)
                self.assertIn("after:", params['q'])
                return mock_list_emails_response_user1
            if 'gmail/v1/users/me/messages' in url and headers['Authorization'] == 'Bearer access_token_user2':
                 # Check query params for user2 (no lastFetchedAt)
                self.assertNotIn("after:", params['q'])
                return mock_list_emails_response_user2_no_new
            # Email detail calls for user1
            if 'msg1_user1' in url and headers['Authorization'] == 'Bearer access_token_user1': return mock_email_detail_response1_user1
            if 'msg2_user1' in url and headers['Authorization'] == 'Bearer access_token_user1': return mock_email_detail_response2_user1
            raise ValueError(f"Unexpected GET request: {url} with headers {headers} and params {params}")

        mock_requests.post.side_effect = requests_post_side_effect
        mock_requests.get.side_effect = requests_get_side_effect

        # --- Call Handler ---
        response = email_fetcher.handler({}, None)

        # --- Assertions ---
        self.assertEqual(response['statusCode'], 200)
        self.assertIn("Job finished. Processed: 2", json.loads(response['body'])['message'])

        # Secrets Manager called once
        mock_secrets_manager.get_secret_value.assert_called_once_with(SecretId='test/gmail/oauth')
        # DynamoDB scan called
        mock_dynamodb.Table.return_value.scan.assert_called_once_with(Limit=5)

        # Token refresh calls
        mock_requests.post.assert_any_call(email_fetcher.GOOGLE_TOKEN_URL, data=unittest.mock.ANY) # Check general structure
        self.assertEqual(mock_requests.post.call_count, 2)


        # DynamoDB updates
        expected_update_user1 = call(
            Key={'userId': 'user1'},
            UpdateExpression='SET lastFetchedAt = :lfa, needsReauth = :nr',
            ExpressionAttributeValues={':lfa': expected_iso_time, ':nr': False}
        )
        expected_update_user2 = call(
            Key={'userId': 'user2'},
            UpdateExpression='SET lastFetchedAt = :lfa, needsReauth = :nr',
            ExpressionAttributeValues={':lfa': expected_iso_time, ':nr': False}
        )
        mock_dynamodb.Table.return_value.update_item.assert_has_calls([expected_update_user1, expected_update_user2], any_order=True)

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth',
        'MAX_USERS_PER_INVOCATION': '1'
    })
    @patch('src.email_fetcher.secrets_manager')
    @patch('src.email_fetcher.dynamodb')
    @patch('src.email_fetcher.requests')
    @patch('src.email_fetcher.datetime')
    def test_handler_invalid_grant_for_user(self, mock_datetime, mock_requests, mock_dynamodb, mock_secrets_manager):
        mock_now = datetime.datetime(2023, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        mock_datetime.datetime.utcnow.return_value = mock_now
        expected_iso_time = "2023-01-01T12:00:00Z"

        mock_secrets_manager.get_secret_value.return_value = {
            'SecretString': json.dumps({'GOOGLE_CLIENT_ID': 'id', 'GOOGLE_CLIENT_SECRET': 'secret'})}

        mock_user_invalid = {'userId': 'user_invalid', 'refreshToken': 'bad_refresh_token'}
        mock_dynamodb.Table.return_value.scan.return_value = {'Items': [mock_user_invalid]}

        # Mock Google OAuth Token Refresh to fail with InvalidGrantError
        mock_failed_refresh_response = MagicMock()
        mock_failed_refresh_response.raise_for_status.side_effect = requests.exceptions.RequestException(
            response=MagicMock(status_code=400, json=lambda: {"error": "invalid_grant"}, text='{"error": "invalid_grant"}')
        )
        mock_requests.post.return_value = mock_failed_refresh_response

        response = email_fetcher.handler({}, None)

        self.assertEqual(response['statusCode'], 200) # Handler itself succeeds
        self.assertIn("Processed: 1", json.loads(response['body'])['message']) # Processed attempt

        # Verify DynamoDB update for needsReauth
        mock_dynamodb.Table.return_value.update_item.assert_called_once_with(
            Key={'userId': 'user_invalid'},
            UpdateExpression='SET needsReauth = :nr, lastFetchedAt = :lfa', # Order might vary
            ExpressionAttributeValues={':nr': True, ':lfa': expected_iso_time}
        )
        # Ensure Gmail API was not called
        mock_requests.get.assert_not_called()


    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth',
        'MAX_USERS_PER_INVOCATION': '10'
    })
    @patch('src.email_fetcher.secrets_manager')
    @patch('src.email_fetcher.dynamodb')
    def test_handler_no_users_found(self, mock_dynamodb, mock_secrets_manager):
        mock_secrets_manager.get_secret_value.return_value = { # Still need secrets for initial setup
            'SecretString': json.dumps({'GOOGLE_CLIENT_ID': 'id', 'GOOGLE_CLIENT_SECRET': 'secret'})}
        mock_dynamodb.Table.return_value.scan.return_value = {'Items': []} # No users

        response = email_fetcher.handler({}, None)
        self.assertEqual(response['statusCode'], 200)
        self.assertIn("No users to process", json.loads(response['body'])['message'])

    @patch.dict(os.environ, {}) # Missing env vars
    def test_handler_missing_env_vars(self):
        response = email_fetcher.handler({}, None)
        self.assertEqual(response['statusCode'], 500)
        self.assertIn("Server configuration error", json.loads(response['body'])['error'])

    @patch.dict(os.environ, {
        'DYNAMO_TABLE_NAME': 'TestUserTokensTable',
        'SECRETS_MANAGER_SECRET_NAME': 'test/gmail/oauth',
        'MAX_USERS_PER_INVOCATION': '1'
    })
    @patch('src.email_fetcher.secrets_manager') # Mock secrets_manager
    @patch('src.email_fetcher.get_users_from_dynamodb') # Mock higher level function
    def test_handler_fetch_emails_general_failure(self, mock_get_users, mock_secrets):
        mock_secrets.get_secret_value.return_value = {
            'SecretString': json.dumps({'GOOGLE_CLIENT_ID': 'id', 'GOOGLE_CLIENT_SECRET': 'secret'})
        }
        mock_get_users.return_value = [{'userId': 'user1', 'refreshToken': 'token1'}]

        # Make process_user raise a generic exception
        with patch('src.email_fetcher.process_user', side_effect=Exception("Gmail API down")):
            response = email_fetcher.handler({}, None)

        self.assertEqual(response['statusCode'], 200) # Job completes
        body = json.loads(response['body'])
        self.assertEqual(body['message'], "Job finished. Processed: 0, Failed: 1")
        # We expect process_user to be called, but it fails. DynamoDB update within process_user might not happen.
        # The main handler catches this and reports failure for this user.


if __name__ == '__main__':
    # If you need to add src to path for local execution:
    # import sys
    # sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
    unittest.main()
