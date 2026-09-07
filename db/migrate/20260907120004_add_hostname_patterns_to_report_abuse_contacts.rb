# frozen_string_literal: true

# nameserver_patterns was only ever matched against a domain's nameservers, so
# a provider was found only when the site also used that provider's DNS. The
# same globs identify a provider just as well in a CNAME target, a reverse
# lookup or an MX exchange, and those are what actually name the host of a
# phishing page.
#
# Renaming the column outright breaks a rolling deploy, because the running
# release still reads the old name. So this adds the new column, copies what is
# there, and the model moves its reads over. nameserver_patterns is left in
# place, unread, for a later migration to drop once this release is out.
class AddHostnamePatternsToReportAbuseContacts < ActiveRecord::Migration[8.1]
  def up
    add_column :report_abuse_contacts, :hostname_patterns, :jsonb, default: []

    Report::AbuseContact.reset_column_information

    say_with_time "copying nameserver_patterns into hostname_patterns" do
      Report::AbuseContact.unscoped.update_all(
        "hostname_patterns = COALESCE(nameserver_patterns, '[]'::jsonb)"
      )
    end
  end

  def down
    remove_column :report_abuse_contacts, :hostname_patterns
  end
end
