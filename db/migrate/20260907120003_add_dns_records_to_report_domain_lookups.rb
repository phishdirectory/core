# frozen_string_literal: true

# Only A and AAAA records were resolved, which answers "which addresses serve
# this" but not "who do I report this to". A phishing site on platform hosting
# is reached by a CNAME, and its address is a shared anycast one that belongs
# to a CDN rather than the platform serving the page.
#
# dns_records holds the whole zone picture keyed by record type, so a case
# carries the evidence a human needs to route a report by hand and the matcher
# has hostnames to work with. a_records and aaaa_records stay as they are: the
# abuse contact matcher reads them on every case, and the domain_info snapshot
# already stored on existing cases uses those keys.
class AddDnsRecordsToReportDomainLookups < ActiveRecord::Migration[8.1]
  def change
    add_column :report_domain_lookups, :dns_records, :jsonb, default: {}
  end
end
