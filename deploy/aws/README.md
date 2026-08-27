# Alternative deployment: AWS Lambda + EventBridge Scheduler

The default production deployment is GitHub Actions (see the top-level README). This directory documents
the serverless alternative. It is documented, not provisioned — nothing here runs until you create it.

```
EventBridge Scheduler (cron(0 8 * * ? *), timezone America/New_York)
        ↓
Lambda (python3.12, handler deploy/aws/handler.lambda_handler, 512 MB, timeout 600 s)
        ↓
Arkham pipeline  ←→  S3 object with the SQLite state
        ↓
Discord webhook → private Arkham channel → phone notification
```

## Steps

1. Build a deployment package (Arkham + pinned deps):
   ```bash
   pip install -r requirements.txt --target build/ && cp -r arkham deploy/aws/handler.py build/ && (cd build && zip -r ../arkham-lambda.zip .)
   ```
2. Create an S3 bucket for state (private, default encryption on) and an IAM role for the function with
   only: `s3:GetObject`/`s3:PutObject` on that one key, CloudWatch Logs write, and read access to the
   secrets you inject. No other permissions (least privilege).
3. Create the function with environment variables mirroring `.env.example` (use Secrets Manager or SSM
   Parameter Store references for `DISCORD_WEBHOOK_URL`, `GEMINI_API_KEY`, `NVD_API_KEY`; the webhook URL is
   a credential — anyone holding it can post into the channel), plus `ARKHAM_S3_BUCKET=<bucket>`,
   `ARKHAM_DB_PATH=/tmp/arkham.db`. No Twilio settings are needed unless `ARKHAM_DELIVERY_PROVIDER=twilio`.
4. Create the timezone-aware schedule (no manual UTC math, DST handled by AWS):
   ```bash
   aws scheduler create-schedule --name arkham-daily \
     --schedule-expression "cron(0 8 * * ? *)" \
     --schedule-expression-timezone "America/New_York" \
     --flexible-time-window '{"Mode":"OFF"}' \
     --target '{"Arn":"<lambda-arn>","RoleArn":"<scheduler-role-arn>","Input":"{}"}'
   ```
5. Test without sending: invoke with payload `{"dry_run": true}`; send a real brief now with `{"force": true}`.
   (Run `python -m arkham test-delivery` locally with the same webhook first to confirm the channel.)

Cost depends on the AWS account, region, execution duration, S3 usage, and current provider pricing. Check the AWS pricing pages and billing console; this repository does not assume free-tier eligibility.
