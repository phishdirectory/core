# frozen_string_literal: true

# Hosting providers are matched by the addresses a domain resolves to, and
# DigitalOcean publishes IPv6 allocations alongside its IPv4 ones. Only A
# records were stored, so an IPv6-only host was never matched and its abuse
# desk never heard about the site.
#
# Kept separate from a_records rather than mixed into it: the column name says
# A records, and the case report renders the two lists under their own headings.
class AddAaaaRecordsToReportDomainLookups < ActiveRecord::Migration[8.1]
  def change
    add_column :report_domain_lookups, :aaaa_records, :jsonb, default: []
  end
end
