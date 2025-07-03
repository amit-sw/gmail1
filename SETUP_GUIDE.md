# Gmail Assistant Setup Guide

This guide provides instructions for setting up the necessary Google Cloud credentials, AWS resources, and deploying the serverless Gmail Assistant application.

## Prerequisites

1.  **AWS Account**: You'll need an AWS account with permissions to create IAM roles, Lambda functions, API Gateway, DynamoDB tables, EventBridge rules, and Secrets Manager secrets.
2.  **AWS SAM CLI**: Install the AWS Serverless Application Model (SAM) CLI. [Installation Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html).
3.  **Python**: Python 3.10 (as specified in `template.yaml`) should be installed locally for SAM CLI to build the deployment package.
4.  **Docker**: Docker is required by SAM CLI for building Lambda deployment packages, especially if there are native dependencies (though not strictly for this pure Python project, it's good practice to have it installed). [Installation Guide](https://docs.docker.com/get-docker/).
5.  **Google Cloud Account**: You'll need a Google Cloud Platform account to set up OAuth 2.0 credentials.

## Step 1: Configure Google OAuth 2.0 Credentials

1.  **Go to Google Cloud Console**: Navigate to [https://console.cloud.google.com/](https://console.cloud.google.com/).
2.  **Create a new project** or select an existing one.
3.  **Enable Gmail API**:
    *   In the navigation menu, go to "APIs & Services" > "Library".
    *   Search for "Gmail API" and enable it for your project.
4.  **Configure OAuth Consent Screen**:
    *   Go to "APIs & Services" > "OAuth consent screen".
    *   Choose "User Type":
        *   **Internal**: If you are a Google Workspace user and the app is only for users within your organization.
        *   **External**: For all other users (including personal Gmail accounts). If you choose External and your app is not verified, it will be subject to limitations (e.g., unverified app screen, limited number of refresh tokens). For personal use, this is usually fine.
    *   Fill in the required information (App name, User support email, Developer contact information).
    *   **Scopes**: Click "Add or Remove Scopes". Search for and add the `https://www.googleapis.com/auth/gmail.readonly` scope. Click "Update".
    *   **Test Users** (if External and in testing phase): Add your Google account email address as a test user.
    *   Save and continue.
5.  **Create OAuth 2.0 Client ID**:
    *   Go to "APIs & Services" > "Credentials".
    *   Click "+ CREATE CREDENTIALS" > "OAuth client ID".
    *   Select "Application type": **Web application**.
    *   Give it a name (e.g., "Gmail Assistant Lambda").
    *   **Authorized redirect URIs**: This is crucial.
        *   You will get the base URL for this after deploying the SAM application for the first time (see Step 3 Output `OAuthCallbackApiEndpoint`).
        *   The format will be `https://{api-id}.execute-api.{region}.amazonaws.com/{Stage}/oauth2callback`.
        *   For example: `https://abcdef1234.execute-api.us-east-1.amazonaws.com/Prod/oauth2callback`.
        *   **You must add this exact URI once known.** You can add a placeholder like `http://localhost` initially if needed, but it must be updated after the first deployment for the OAuth flow to work.
    *   Click "CREATE".
6.  **Note Your Credentials**:
    *   A dialog will appear showing your **Client ID** and **Client Secret**.
    *   **Copy these values immediately and store them securely.** You will need them in the next step.

## Step 2: Store Google Credentials in AWS Secrets Manager

1.  **Go to AWS Secrets Manager**: Navigate to the AWS Management Console and open Secrets Manager.
2.  **Store a new secret**:
    *   Click "Store a new secret".
    *   Select "Secret type": **Other type of secret**.
    *   Under "Key/value pairs":
        *   Key: `GOOGLE_CLIENT_ID`, Value: `YOUR_GOOGLE_CLIENT_ID` (from Step 1.6)
        *   Click "+ Add row".
        *   Key: `GOOGLE_CLIENT_SECRET`, Value: `YOUR_GOOGLE_CLIENT_SECRET` (from Step 1.6)
    *   Encryption key: You can use the default `aws/secretsmanager` or a custom KMS key.
    *   Click "Next".
3.  **Secret name**:
    *   Enter `gmail/oauth` (this is the default expected by the `template.yaml`). If you use a different name, you'll need to pass it as a parameter during SAM deployment.
    *   Add a description if you like.
    *   Click "Next".
4.  **Configure rotation (optional)**: You can configure automatic rotation if desired, but it's not required for this application's core functionality with long-lived refresh tokens.
    *   Click "Next".
5.  **Review and Store**: Review the details and click "Store".

## Step 3: Deploy the SAM Application

1.  **Clone the Repository** (if you haven't already):
    ```bash
    # git clone <repository_url>
    # cd <repository_directory>
    ```
2.  **Build the Application**:
    ```bash
    sam build
    ```
    This command builds your Lambda deployment packages.
3.  **Deploy the Application (Guided)**:
    ```bash
    sam deploy --guided
    ```
    This will prompt you for deployment parameters:
    *   **Stack Name**: Choose a name for your CloudFormation stack (e.g., `gmail-assistant-app`).
    *   **AWS Region**: Enter the AWS region you want to deploy to (e.g., `us-east-1`).
    *   **Parameter SecretsManagerSecretName**: Press Enter to accept the default (`gmail/oauth`) if you used that name in Step 2. Otherwise, provide the name you used.
    *   **Confirm changes before deploy**: `Y` (recommended to review changes).
    *   **Allow SAM CLI IAM role creation**: `Y`.
    *   **Disable rollback**: `n` (allows rollback on failure).
    *   **Save arguments to configuration file**: `Y` (saves your choices to `samconfig.toml` for future deployments).
    *   **SAM configuration environment**: `default` (or choose a custom one).

    SAM CLI will then deploy your application using AWS CloudFormation. Wait for the deployment to complete.

4.  **Note the API Endpoint**:
    *   After a successful deployment, look for the `Outputs` section in the SAM CLI output (or in the CloudFormation stack outputs in the AWS console).
    *   Find the value for `OAuthCallbackApiEndpoint`. It will look something like:
        `https://abcdef1234.execute-api.us-east-1.amazonaws.com/Prod/oauth2callback`
    *   **This is your `CALLBACK_URL`**.

## Step 4: Update Google OAuth Client with Correct Redirect URI

1.  Go back to your Google Cloud Console > "APIs & Services" > "Credentials".
2.  Click the edit icon for the OAuth 2.0 Client ID you created in Step 1.
3.  Under "Authorized redirect URIs", click "+ ADD URI".
4.  Paste the `OAuthCallbackApiEndpoint` value you obtained in Step 3.4.
5.  Click "SAVE".

## Step 5: Initiate First Authorization

1.  **Construct the Authorization URL**:
    You need to create a URL with the following structure. Replace placeholders with your actual values:
    *   `{YOUR_API_GATEWAY_DOMAIN_AND_STAGE}`: This is the part of your `OAuthCallbackApiEndpoint` *before* `/oauth2callback`. For example, `https://abcdef1234.execute-api.us-east-1.amazonaws.com/Prod`.
    *   `{YOUR_GOOGLE_CLIENT_ID}`: Your Google Client ID from Step 1.6.
    *   `{YOUR_CALLBACK_URL}`: The full `OAuthCallbackApiEndpoint` from Step 3.4.

    ```
    https://accounts.google.com/o/oauth2/v2/auth?
    client_id={YOUR_GOOGLE_CLIENT_ID}&
    redirect_uri={YOUR_CALLBACK_URL}&
    response_type=code&
    scope=https://www.googleapis.com/auth/gmail.readonly&
    access_type=offline&
    prompt=consent
    ```

    **Example (ensure there are no line breaks in the actual URL):**
    ```
    https://accounts.google.com/o/oauth2/v2/auth?client_id=your-client-id.apps.googleusercontent.com&redirect_uri=https://abcdef1234.execute-api.us-east-1.amazonaws.com/Prod/oauth2callback&response_type=code&scope=https://www.googleapis.com/auth/gmail.readonly&access_type=offline&prompt=consent
    ```

2.  **Open the URL in your browser**.
3.  You will be prompted to log in to your Google account (if not already logged in) and then to grant the application permission to access your Gmail (readonly).
4.  After granting permission, you should be redirected to your `CALLBACK_URL` and see a "Authorization Successful!" message.
5.  Your refresh token is now stored in DynamoDB.

## Step 6: Monitor the Application

*   **EventBridge Rule**: The `EmailFetcherJob` Lambda is scheduled to run every 5 minutes by default (see `template.yaml`).
*   **CloudWatch Logs**:
    *   Logs for `OAuthCallbackHandlerFunction` can be found in CloudWatch Logs under the log group `/aws/lambda/{YourStackName}-OAuthCallbackHandlerFunction-{RandomSuffix}`.
    *   Logs for `EmailFetcherJobFunction` can be found under `/aws/lambda/{YourStackName}-EmailFetcherJobFunction-{RandomSuffix}`.
    *   Check these logs for successful email fetching operations or any errors.
*   **DynamoDB**: You can inspect the `UserTokens` table in the DynamoDB console to see stored `userId`, `refreshToken`, `lastFetchedAt`, and `needsReauth` status.

## Future Deployments

If you make changes to the Lambda code or `template.yaml`:
1.  Build: `sam build`
2.  Deploy: `sam deploy` (it will use settings from `samconfig.toml` if saved)

## Troubleshooting

*   **`redirect_uri_mismatch` error from Google**: Ensure the "Authorized redirect URI" in your Google Cloud OAuth client settings *exactly* matches the `OAuthCallbackApiEndpoint` output by SAM, including `https://` and any trailing slashes if present (though typically there are none for this path).
*   **"Refresh token not received"**: Make sure `prompt=consent` and `access_type=offline` are in your authorization URL. A refresh token is typically only issued the first time a user authorizes, unless `prompt=consent` is used to force the consent screen and re-issue of a refresh token.
*   **Lambda errors in CloudWatch**: Check the logs for specific error messages. Common issues include IAM permissions, incorrect environment variable configuration, or bugs in the Lambda code.
*   **`invalid_grant` in `EmailFetcherJob` logs**: This means the refresh token for a user is no longer valid. The user will be flagged with `needsReauth: true` in DynamoDB. They would need to go through the authorization flow (Step 5) again.
*   **Secrets Manager Access Denied**: Ensure the Lambda execution roles have the correct permissions to access the secret (this is configured in `template.yaml`). Also, verify the secret name matches.

This completes the setup guide.
```
