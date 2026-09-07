# frozen_string_literal: true

module Report
  # Resolves the full DNS picture for a domain.
  #
  # A report is only useful if it reaches the party that can act on it, and no
  # single record names that party. The addresses find a host that runs its own
  # ranges; a CNAME names a platform whose addresses are shared anycast ones; a
  # reverse lookup names the host when the forward records do not; MX names who
  # carries the mail side. Sweeping the zone gives the matcher hostnames to work
  # with and gives a human the evidence to route a report by hand.
  #
  # Usage:
  #   records = Report::DnsSweepService.new.sweep("example.com")
  #   records["CNAME"]  # => ["site.vercel-dns.com"]
  #
  # Not swept: DNSKEY and DS have no typed class in Resolv and say nothing about
  # who to report to, and SRV is only meaningful under a _service._proto label
  # rather than on the domain itself.
  class DnsSweepService < BaseService
    TIMEOUT = 5

    # Reverse lookups cost one query per address, so cap how many are tried.
    MAX_REVERSE_LOOKUPS = 4

    RECORD_TYPES = {
      "A" => Resolv::DNS::Resource::IN::A,
      "AAAA" => Resolv::DNS::Resource::IN::AAAA,
      "CNAME" => Resolv::DNS::Resource::IN::CNAME,
      "NS" => Resolv::DNS::Resource::IN::NS,
      "MX" => Resolv::DNS::Resource::IN::MX,
      "TXT" => Resolv::DNS::Resource::IN::TXT,
      "SOA" => Resolv::DNS::Resource::IN::SOA,
      "CAA" => Resolv::DNS::Resource::IN::CAA
    }.freeze

    # Sweep every record type for a domain
    #
    # @param domain [String] the domain to resolve
    # @return [Hash] records keyed by type, empty types omitted
    def sweep(domain)
      domain = domain.to_s.strip.downcase
      return {} if domain.blank?

      records = {}

      Timeout.timeout(TIMEOUT) do
        Resolv::DNS.open do |dns|
          RECORD_TYPES.each do |label, resource|
            values = resolve(dns, domain, label, resource)
            records[label] = values if values.present?
          end
        end
      end

      records["PTR"] = reverse_lookups(records)
      records.compact_blank
    rescue StandardError => e
      # A domain that does not resolve is still worth reporting on its
      # registration record, so a failed sweep degrades to what was collected.
      log_debug("DNS sweep failed for #{domain}: #{e.message}")
      records || {}
    end

    # Hostnames that name the party serving the content.
    #
    # A CNAME target and a reverse lookup both name the machine or platform the
    # page is actually served from, which is who can take it down.
    #
    # @param records [Hash] output of #sweep
    # @return [Array<String>] hostnames, lowercased and without trailing dots
    def self.serving_hostnames(records)
      records = records.to_h.with_indifferent_access

      normalize(
        Array(records["CNAME"]) +
        Array(records["PTR"]).map { |_address, name| name }
      )
    end

    # Hostnames that name only the DNS operator.
    #
    # This is the weakest signal for who hosts a page and is tried last:
    # github.com delegates to Route 53 but is served by GitHub, so matching on
    # nameservers first would send the report to the wrong company.
    #
    # @param records [Hash] output of #sweep
    # @return [Array<String>] hostnames, lowercased and without trailing dots
    def self.nameserver_hostnames(records)
      normalize(Array(records.to_h.with_indifferent_access["NS"]))
    end

    # Every hostname the sweep found, in precedence order
    #
    # @param records [Hash] output of #sweep
    # @return [Array<String>]
    def self.hostnames(records)
      (serving_hostnames(records) + nameserver_hostnames(records)).uniq
    end

    def self.normalize(names)
      names.compact_blank.map { |name| name.to_s.downcase.chomp(".") }.uniq
    end
    private_class_method :normalize

    private

    def resolve(dns, domain, label, resource)
      records = dns.getresources(domain, resource)

      case label
      when "A", "AAAA" then records.map { |r| r.address.to_s }
      when "CNAME", "NS" then records.map { |r| r.name.to_s }
      when "MX" then records.map { |r| { "preference" => r.preference, "exchange" => r.exchange.to_s } }
      when "TXT" then records.map { |r| r.strings.join }
      when "SOA" then soa(records.first)
      when "CAA" then records.map { |r| { "flags" => r.flags, "tag" => r.tag, "value" => r.value } }
      end
    rescue StandardError => e
      log_debug("Could not resolve #{label} for #{domain}: #{e.message}")
      nil
    end

    def soa(record)
      return nil if record.nil?

      {
        "mname" => record.mname.to_s,
        "rname" => record.rname.to_s,
        "serial" => record.serial
      }
    end

    # A reverse lookup often names the host outright, which is what a shared
    # address cannot do.
    def reverse_lookups(records)
      addresses = (Array(records["A"]) + Array(records["AAAA"])).first(MAX_REVERSE_LOOKUPS)
      return {} if addresses.empty?

      addresses.each_with_object({}) do |address, names|
        name = reverse_lookup(address)
        names[address] = name if name.present?
      end
    end

    def reverse_lookup(address)
      Timeout.timeout(TIMEOUT) { Resolv.getname(address) }
    rescue StandardError
      nil
    end
  end
end
