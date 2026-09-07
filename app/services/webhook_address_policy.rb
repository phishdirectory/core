# frozen_string_literal: true

require "ipaddr"
require "resolv"

# Decides whether a webhook URL is safe to call.
#
# Webhook URLs are supplied by services, and the worker calls them from inside
# our network. Without a check, a service can point one at 127.0.0.1, at a
# private range, or at the cloud metadata endpoint on 169.254.169.254 and use
# our own worker to reach things it cannot reach itself.
#
# The check runs twice: once when the URL is saved, and again immediately
# before delivery, because the name can resolve somewhere else by then.
class WebhookAddressPolicy
  BLOCKED_RANGES = [
    IPAddr.new("0.0.0.0/8"),        # this network
    IPAddr.new("10.0.0.0/8"),       # private
    IPAddr.new("127.0.0.0/8"),      # loopback
    IPAddr.new("169.254.0.0/16"),   # link local, includes cloud metadata
    IPAddr.new("172.16.0.0/12"),    # private
    IPAddr.new("192.168.0.0/16"),   # private
    IPAddr.new("100.64.0.0/10"),    # carrier grade NAT
    IPAddr.new("::1/128"),          # loopback
    IPAddr.new("fc00::/7"),         # unique local
    IPAddr.new("fe80::/10")         # link local
  ].freeze

  BLOCKED_HOSTNAMES = %w[localhost metadata.google.internal].freeze

  class << self
    # Cheap checks only: a literal IP in a blocked range, or an obviously
    # local name. Does no DNS, so it is safe to call from a validation.
    def obviously_internal?(url)
      host = host_for(url)
      return true if host.blank?
      return true if BLOCKED_HOSTNAMES.include?(host.downcase)
      return true if host.downcase.end_with?(".localhost", ".internal", ".local")

      literal = parse_ip(host)
      literal ? blocked_ip?(literal) : false
    end

    # Full check including DNS resolution. Used at delivery time.
    def internal?(url)
      return true if obviously_internal?(url)
      return false unless resolve?

      addresses = resolve(host_for(url))
      # A name we cannot resolve is treated as unsafe: we would rather drop a
      # delivery than follow a name we know nothing about.
      return true if addresses.empty?

      addresses.any? { |address| blocked_ip?(address) }
    end

    def blocked_ip?(address)
      BLOCKED_RANGES.any? { |range| range.include?(address) }
    end

    private

    def host_for(url)
      URI.parse(url.to_s).host
    rescue URI::InvalidURIError
      nil
    end

    def parse_ip(host)
      IPAddr.new(host)
    rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
      nil
    end

    def resolve(host)
      return [] if host.blank?

      Resolv.getaddresses(host).filter_map { |address| parse_ip(address) }
    rescue StandardError
      []
    end

    # DNS lookups are disabled in the test environment so the suite stays
    # hermetic. The policy itself is unit tested directly.
    def resolve?
      Rails.application.config.x.webhooks.resolve_addresses != false
    end
  end
end
