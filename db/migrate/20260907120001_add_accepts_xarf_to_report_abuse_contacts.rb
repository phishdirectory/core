# frozen_string_literal: true

# Some abuse desks process their mailbox with automated tooling and drop
# anything that is only prose. DigitalOcean is the first of these: it asks for
# an X-ARF (https://github.com/abusix/xarf) attachment on every report.
#
# Contacts with this flag get the X-ARF envelope from Report::AbuseReportMailer
# instead of the plain HTML report. Everyone else is unaffected.
class AddAcceptsXarfToReportAbuseContacts < ActiveRecord::Migration[8.1]
  def change
    add_column :report_abuse_contacts, :accepts_xarf, :boolean, default: false, null: false
  end
end
