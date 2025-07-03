## 1. Overview

A serverless Gmail Assistant that:

- Allows a user to authorize via OAuth 2.0 once.
- Stores refresh tokens securely.
- Periodically fetches new emails via the Gmail API.
- Processes emails (e.g. metadata extraction, classification, forwarding).

Key AWS services:

- **API Gateway** – exposes HTTP endpoints for OAuth callbacks and any user-triggered operations.
- **AWS Lambda** – implements the OAuth callback handler, token refresher & email fetcher.
- **Amazon DynamoDB** – stores user records and refresh tokens.
- **AWS Secrets Manager** – holds the Google OAuth client credentials.
- **EventBridge (CloudWatch Events)** – schedules the periodic fetch job.
- **CloudWatch Logs/Alarms** – captures function logs and alerts on errors.

---

## 2. Architecture Diagram

```
┌────────────┐         ┌─────────────────────┐         ┌───────────────────┐
│  User’s    │──Login─>│ API Gateway /       │─Invoke─>│ Lambda: OAuth     │
│  Browser   │         │ OAuth Callback      │ Handler │ Callback Handler  │
└────────────┘         └─────────────────────┘         └───────────────────┘
                                                            │
                                                            ▼
                                                     ┌────────────────┐
                                                     │ DynamoDB:      │
                                                     │ UserTokens     │
                                                     └────────────────┘

          EventBridge
      (e.g. every 5 mins)
             │
             ▼
┌───────────────────────────┐    Uses    ┌────────────────────────┐
│ Lambda: EmailFetcherJob   │───────────>│ Gmail API (via HTTP)   │
│  - Loads refresh token    │            └────────────────────────┘
│  - Refreshes access token │
│  - Fetches new emails     │
│  - Processes & persists   │
└───────────────────────────┘
             │
             ▼
┌───────────────────────────┐
│   (Optional) SNS/SQS      │
│   for downstream jobs     │
└───────────────────────────┘
```

---

## 3. Components

### 3.1. API Gateway

- **Endpoint**: `GET /oauth2callback`
- **Integration**: Lambda “OAuthCallbackHandler”
- **Purpose**: Receives Google’s authorization code, returns success page.

### 3.2. Lambda: OAuthCallbackHandler

- **Trigger**: API Gateway `/oauth2callback`
- **Steps**:
  1. Read `code` query parameter.
  2. Call Google token endpoint to exchange code for `access_token` & **`refresh_token`**.
  3. Store `{ userId, refreshToken, expiry }` in DynamoDB.
  4. Return a “Success—You may close this window” HTML response.

- **Environment Variables**:
  - `GOOGLE_CLIENT_ID` & `GOOGLE_CLIENT_SECRET` (from Secrets Manager)
  - `DYNAMO_TABLE_NAME`

### 3.3. DynamoDB: UserTokens

- **Primary Key**: `userId` (string, e.g. Google sub)
- **Attributes**:  
  - `refreshToken` (string)  
  - `lastFetchedAt` (timestamp)

- **Provisioning**: On-demand or minimal RCU/WCU (low throughput).

### 3.4. Lambda: EmailFetcherJob

- **Trigger**: EventBridge rule (e.g. cron every 5 minutes).
- **Steps** per user record:
  1. Load `refreshToken`.
  2. Call Google OAuth token endpoint to get new `access_token`.
  3. Call Gmail API `users.messages.list` with `q=is:unread` since `lastFetchedAt`.
  4. For each message ID: call `users.messages.get`, process as needed.
  5. Update `lastFetchedAt` in DynamoDB.
  6. (Optional) Publish processing result to SNS/SQS for downstream Consumers.

- **Environment Variables**:
  - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
  - `DYNAMO_TABLE_NAME`
  - `MAX_USERS_PER_INVOCATION` (to batch process)

### 3.5. AWS Secrets Manager

- **Secret**: `gmail/oauth`
  - `GOOGLE_CLIENT_ID`
  - `GOOGLE_CLIENT_SECRET`
- Grant read access to both Lambdas via their IAM role.

### 3.6. EventBridge Rule

- Cron: `rate(5 minutes)` (or as needed).
- Target: `EmailFetcherJob` Lambda.

---

## 4. Security & IAM

1. **Lambda Execution Roles**  
   - **OAuthCallbackHandlerRole**:  
     - `secretsmanager:GetSecretValue` on `gmail/oauth`  
     - `dynamodb:PutItem` on `UserTokens` table  
     - `logs:CreateLogGroup/Stream/PutLogEvents`

   - **EmailFetcherJobRole**:  
     - `secretsmanager:GetSecretValue` on `gmail/oauth`  
     - `dynamodb:GetItem/UpdateItem/Scan` on `UserTokens`  
     - `logs:...`  

2. **API Gateway**  
   - Publicly accessible only for the OAuth callback endpoint.
   - Use WAF or API keys if you want to limit who can invoke (optional).

3. **Network**  
   - All calls to Gmail API go out to the internet via NAT or Internet Gateway.

---

## 5. Deployment

You can deploy via **AWS SAM**, **Serverless Framework**, or **Terraform**. Below is a SAM snippet:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:

  OAuthCallbackHandler:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/oauth_callback.handler
      Runtime: nodejs18.x
      Environment:
        Variables:
          DYNAMO_TABLE_NAME: !Ref UserTokensTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UserTokensTable
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action: secretsmanager:GetSecretValue
              Resource: arn:aws:secretsmanager:us-west-2:123456789012:secret:gmail/oauth-*

  EmailFetcherJob:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/email_fetcher.job
      Runtime: python3.10
      Environment:
        Variables:
          DYNAMO_TABLE_NAME: !Ref UserTokensTable
      Policies:
        - DynamoDBReadWritePolicy:
            TableName: !Ref UserTokensTable
        - Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action: secretsmanager:GetSecretValue
              Resource: arn:aws:secretsmanager:us-west-2:123456789012:secret:gmail/oauth-*
      Events:
        ScheduledFetch:
          Type: Schedule
          Properties:
            Schedule: rate(5 minutes)

  UserTokensTable:
    Type: AWS::Serverless::SimpleTable
    Properties:
      PrimaryKey:
        Name: userId
        Type: String
```

### 5.1. Secrets Setup

1. In AWS Console → Secrets Manager → **Store a new secret**.  
2. Key/value pairs:
   - `GOOGLE_CLIENT_ID` : _your-client-id.apps.googleusercontent.com_
   - `GOOGLE_CLIENT_SECRET` : _your-client-secret_  
3. Name the secret, e.g. `gmail/oauth`.

### 5.2. Environment Variables

- The Lambda functions will read `GOOGLE_CLIENT_ID` & `GOOGLE_CLIENT_SECRET` at runtime by calling Secrets Manager.
- Ensure your SAM/CloudFormation template references the secret’s ARN in the IAM policies.

### 5.3. DNS / Custom Domain (optional)

- If you want a friendly callback URL, set up a Custom Domain in API Gateway and map `/oauth2callback`.

---

## 6. Running the App

1. **Initial Authorization**  
   - Point the user’s browser to  
     ```
     https://{api-domain}/oauth2callback?
       client_id={CLIENT_ID}&
       redirect_uri={CALLBACK_URL}&
       response_type=code&
       scope=https://www.googleapis.com/auth/gmail.readonly&
       access_type=offline&
       prompt=consent
     ```
   - They log in and grant permissions.  
   - OAuthCallback Lambda stores their refresh token.

2. **Periodic Fetching**  
   - EventBridge triggers the EmailFetcherJob every 5 minutes.  
   - Logs appear in CloudWatch under `/aws/lambda/EmailFetcherJob`.

3. **Inspecting Results**  
   - Processed email data can be forwarded to SNS, stored in S3, or pushed into DynamoDB/SQS for downstream workflows.

4. **Error Handling & Re-auth**  
   - If you get an `invalid_grant` or other token error in EmailFetcherJob, flag the user record (e.g. set `needsReauth = true`), and notify the user to re-login.

---

## 7. Next Steps & Enhancements

- **Add a small front-end** (e.g. React SPA on S3/CloudFront) to manage connected accounts and show status.
- **Support multiple Gmail scopes** (`modify`, `send`, etc.) based on feature set.
- **Use AWS Cognito** if you need your own user-pool and sign-in.
- **Monitoring**: add CloudWatch Alarms on Lambda errors and DynamoDB throttles.
- **Cost Optimization**: tune fetch frequency and batch size per invocation.
