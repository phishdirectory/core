# frozen_string_literal: true

# Action Mailbox Configuration for Postmark Inbound Email
#
# See docs/inbound_email_setup.md for full setup instructions.
#
# Quick reference:
#   - Webhook URL: https://actionmailbox:<password>@phish.directory/rails/action_mailbox/postmark/inbound_emails
#   - Email routing: case_*@cases.phish.directory -> Report::CasesMailbox
#   - Local testing: /rails/conductor/action_mailbox/inbound_emails (with ingress: :relay)
#
# Credentials required:
#   action_mailbox:
#     ingress_password: <secure_password>
