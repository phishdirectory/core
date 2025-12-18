# frozen_string_literal: true

# Inbound email routing for Action Mailbox
#
# Routes emails to the appropriate mailbox based on the recipient address.
# See docs/inbound_email_setup.md for full configuration details.
#
class ApplicationMailbox < ActionMailbox::Base
  # Route emails to case_@cases.phish.directory to the cases mailbox
  # This catches replies to abuse reports we've sent
  routing(/^case_[a-z0-9]+@cases\.phish\.directory$/i => "report/cases")

  # Default - bounce unmatched emails
  routing :all => :bounces
end
