# frozen_string_literal: true

# Job to check domain availability (DNS resolution and HTTP reachability)
# Can process a single domain by ID or batch process domains that need checking
#
# Single domain mode:
#   DomainAvailabilityCheckJob.perform_later(domain_id)
#
# Batch mode (scheduled):
#   DomainAvailabilityCheckJob.perform_later
#
class DomainAvailabilityCheckJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  # Configuration
  BATCH_SIZE = 100
  CHECK_THRESHOLD = 1.hour
  DNS_TIMEOUT = 5
  HTTP_TIMEOUT = 10

  def perform(domain_id = nil)
    if domain_id
      check_single_domain(domain_id)
    else
      check_batch_of_domains
    end
  end

  private

  def check_single_domain(domain_id)
    domain = Phish::Domain.find_by(id: domain_id)
    return unless domain

    result = Domain::AvailabilityService.check(
      domain.domain,
      dns_timeout: DNS_TIMEOUT,
      http_timeout: HTTP_TIMEOUT
    )

    domain.update_availability!(
      dns_resolvable: result[:dns][:resolvable],
      http_reachable: result[:http][:reachable]
    )

    Rails.logger.info(
      "[DomainAvailability] Checked #{domain.domain}: " \
      "DNS=#{result[:dns][:resolvable]}, HTTP=#{result[:http][:reachable]}"
    )
  end

  def check_batch_of_domains
    # Prioritize recently seen domains that need availability checks
    recently_seen = Phish::Domain
      .seen_recently(7.days)
      .needs_availability_check(CHECK_THRESHOLD)
      .order(last_seen_at: :desc)
      .limit(BATCH_SIZE)
      .pluck(:id)

    # Also check domains that were recently added but never checked
    unchecked = Phish::Domain
      .where(availability_checked_at: nil)
      .order(created_at: :desc)
      .limit(BATCH_SIZE)
      .pluck(:id)

    # A domain that is both recently seen and never checked matches both
    # queries. Deduplicate so it is only enqueued once.
    domain_ids = (recently_seen + unchecked).uniq

    Rails.logger.info(
      "[DomainAvailability] Found #{recently_seen.size} recently seen and " \
      "#{unchecked.size} unchecked domains, #{domain_ids.size} to check"
    )

    domain_ids.each do |domain_id|
      # Enqueue individual checks to spread the load
      DomainAvailabilityCheckJob.perform_later(domain_id)
    end
  end
end
