# Inbound Email Setup (Postmark)

This document describes how to configure inbound email handling for the automated reporting system. Emails sent to `case_*@cases.phish.directory` are processed by Action Mailbox and linked to their corresponding report cases.

## Overview

When we send abuse reports, we CC `case_<id>@cases.phish.directory`. When recipients reply, Postmark receives the email and forwards it to our Rails app via webhook. Action Mailbox routes it to `Report::CasesMailbox`, which creates a `Report::CaseEmail` record linked to the case.

```
[Reply Email] → [Postmark Inbound] → [Webhook] → [Action Mailbox] → [CasesMailbox] → [CaseEmail Record]
```

## DNS Configuration

Add an MX record for the `cases` subdomain pointing to Postmark:

```yaml
# DNS Zone: phish.directory
cases:
  - ttl: 300
    type: MX
    value:
      exchange: inbound.postmarkapp.com.
      preference: 10
```

This routes all emails to `*@cases.phish.directory` to Postmark's inbound servers.

## Postmark Configuration

### 1. Enable Inbound Processing

1. Go to **Servers → Your Server → Settings → Inbound**
2. Enable inbound email processing

### 2. Configure Webhook

Set the inbound webhook URL with basic auth credentials:

```
https://actionmailbox:<INGRESS_PASSWORD>@phish.directory/rails/action_mailbox/postmark/inbound_emails
```

Replace `<INGRESS_PASSWORD>` with the value from Rails credentials.

### 3. Webhook Settings

- **Include raw email content**: Yes (required for attachments)
- **Post only on first open**: No

## Rails Configuration

### 1. Generate Ingress Password

```bash
bin/rails runner "puts SecureRandom.base58(32)"
```

### 2. Add to Credentials

```bash
bin/rails credentials:edit
```

Add:

```yaml
action_mailbox:
  ingress_password: <generated_password>
```

For environment-specific credentials:

```bash
bin/rails credentials:edit -e production
```

### 3. Environment Configuration

**Production** (`config/environments/production.rb`):
```ruby
config.action_mailbox.ingress = :postmark
```

**Development** (`config/environments/development.rb`):
```ruby
config.action_mailbox.ingress = :postmark  # For ngrok testing
# or
config.action_mailbox.ingress = :relay     # For conductor UI testing
```

## Email Routing

Emails are routed in `app/mailboxes/application_mailbox.rb`:

```ruby
class ApplicationMailbox < ActionMailbox::Base
  # Route case emails to the cases mailbox
  routing(/^case_[a-z0-9]+@cases\.phish\.directory$/i => "report/cases")

  # Bounce everything else
  routing :all => :bounces
end
```

The `Report::CasesMailbox` (`app/mailboxes/report/cases_mailbox.rb`):
1. Extracts the case number from the To address
2. Finds the corresponding `Report::Case`
3. Creates a `Report::CaseEmail` record with the email content
4. Updates the case's `last_activity_at` timestamp

## Local Development Testing

### Option 1: Conductor UI (No External Setup)

Use the built-in Action Mailbox conductor:

1. Set ingress to relay in `config/environments/development.rb`:
   ```ruby
   config.action_mailbox.ingress = :relay
   ```

2. Visit `http://localhost:3000/rails/conductor/action_mailbox/inbound_emails`

3. Create a new inbound email with:
   - **To**: `case_test123@cases.phish.directory`
   - **From**: `abuse@example.com`
   - **Subject**: `Re: Your phishing report`

4. Submit and check the logs

### Option 2: ngrok + Postmark (Full Integration Test)

1. **Start ngrok**:
   ```bash
   ngrok http 3000
   ```

2. **Allow ngrok hosts** (already configured in development.rb):
   ```ruby
   config.hosts << /.*\.ngrok-free\.app/
   config.hosts << /.*\.ngrok\.io/
   ```

3. **Set ingress to postmark**:
   ```ruby
   config.action_mailbox.ingress = :postmark
   ```

4. **Update Postmark webhook** temporarily:
   ```
   https://actionmailbox:<password>@<your-subdomain>.ngrok-free.app/rails/action_mailbox/postmark/inbound_emails
   ```

5. **Send test email** to `case_test123@cases.phish.directory`

6. **Watch Rails logs** for mailbox processing

## Troubleshooting

### "Blocked hosts" Error

Add the host to `config.hosts` in development.rb:
```ruby
config.hosts << "your-subdomain.ngrok-free.app"
```

### 401 Unauthorized from Postmark

- Check the ingress password matches between credentials and Postmark webhook URL
- Ensure the password is URL-encoded if it contains special characters

### Email Not Routing to CasesMailbox

- Verify the To address matches the pattern: `case_<alphanumeric>@cases.phish.directory`
- Check `ApplicationMailbox` routing rules
- Look for routing in Rails logs: `Routing to report/cases`

### Case Not Found

- The case number in the email address must match an existing `Report::Case.case_number`
- Check the mailbox logs for the extracted case number

## Monitoring

### Postmark Dashboard

- **Activity → Inbound**: View received emails and webhook delivery status
- **Webhooks → Logs**: Check for failed webhook deliveries

### Rails Logs

Successful processing shows:
```
Report::CasesMailbox processing inbound email
  Routed to case: case_t7fvupxzpt2a0b
  Created CaseEmail: rce_...
```

### Database

Check recent inbound emails:
```ruby
Report::CaseEmail.where(direction: :inbound).order(created_at: :desc).limit(10)
```
