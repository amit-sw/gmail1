# Troubleshooting Guide

*   **`redirect_uri_mismatch` error from Google**: Ensure the "Authorized redirect URI" in your Google Cloud OAuth client settings *exactly* matches the `OAuthCallbackApiEndpoint` output by SAM, including `https://` and any trailing slashes if present (though typically there are none for this path).
*   **"Refresh token not received"**: Make sure `prompt=consent` and `access_type=offline` are in your authorization URL. A refresh token is typically only issued the first time a user authorizes, unless `prompt=consent` is used to force the consent screen and re-issue of a refresh token.
*   **Lambda errors in CloudWatch**: Check the logs for specific error messages. Common issues include IAM permissions, incorrect environment variable configuration, or bugs in the Lambda code.
*   **`invalid_grant` in `EmailFetcherJob` logs**: This means the refresh token for a user is no longer valid. The user will be flagged with `needsReauth: true` in DynamoDB. They would need to go through the authorization flow (Step 5) again.
*   **Secrets Manager Access Denied**: Ensure the Lambda execution roles have the correct permissions to access the secret (this is configured in `template.yaml`). Also, verify the secret name matches.
