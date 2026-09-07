# frozen_string_literal: true

module Report
  # Keeps the DigitalOcean abuse contact's IP ranges current.
  #
  # DigitalOcean publishes its allocations as a CSV whose first column is the
  # CIDR block. Report::AbuseContact.find_for_ip matches a phishing domain's A
  # records against those blocks, which is how the pipeline decides that
  # DigitalOcean is the host to notify.
  #
  # Usage:
  #   Report::DigitalOceanRangeService.new.sync
  #
  class DigitalOceanRangeService < BaseService
    RANGES_URL = "https://digitalocean.com/geo/google.csv"
    CONTACT_NAME = "DigitalOcean"

    def sync
      cidrs = parse_cidrs(fetch_ranges)

      if cidrs.empty?
        log_error("Range list was empty", ServiceError.new("no usable CIDR blocks"))
        return { success: false, error: "No IP ranges returned" }
      end

      contact = Report::AbuseContact.find_by(name: CONTACT_NAME)

      unless contact
        return { success: false, error: "#{CONTACT_NAME} abuse contact is not seeded" }
      end

      contact.update!(ip_ranges: cidrs)
      log_info("Stored #{cidrs.size} DigitalOcean IP ranges")

      { success: true, ranges: cidrs.size }
    rescue ServiceError => e
      { success: false, error: e.message }
    end

    private

    def fetch_ranges
      conn = connection(base_url: RANGES_URL, headers: { "Accept" => "text/csv" })
      get(conn, "").to_s
    end

    # Rows look like "5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH". Anything that
    # is not a CIDR block is dropped rather than stored and matched against
    # later.
    def parse_cidrs(body)
      body.each_line.filter_map do |line|
        cidr = line.split(",").first.to_s.strip
        next if cidr.blank?

        IPAddr.new(cidr)
        cidr
      rescue IPAddr::InvalidAddressError
        nil
      end
    end
  end
end
