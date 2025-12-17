# frozen_string_literal: true

module Admin
  class QuickSearchController < BaseController
    # GET /admin/quick_search
    # Returns JSON results for Command-K search
    def index
      query = params[:q].to_s.strip
      return render json: { results: [] } if query.blank?

      results = []

      # Search by prefix to determine type
      case query
      when /^usr_/i
        results += search_users_by_public_id(query)
      when /^svc_/i
        results += search_services_by_public_id(query)
      when /^dom_/i
        results += search_domains_by_public_id(query)
      when /^url_/i
        results += search_urls_by_public_id(query)
      when /^PDU/i
        results += search_users_by_pd_id(query)
      else
        # General search across all types
        results += search_users(query)
        results += search_services(query)
        results += search_domains(query)
        results += search_urls(query)
      end

      render json: { results: results.first(10) }
    end

    private

    def search_users_by_public_id(query)
      user = User.find_by_public_id(query)
      return [] unless user

      [format_user(user)]
    end

    def search_users_by_pd_id(query)
      user = User.find_by(pd_id: query.upcase)
      return [] unless user

      [format_user(user)]
    end

    def search_users(query)
      users = User.where(
        "email ILIKE :q OR username ILIKE :q OR first_name ILIKE :q OR last_name ILIKE :q OR pd_id ILIKE :q",
        q: "%#{query}%"
      ).limit(5)

      users.map { |u| format_user(u) }
    end

    def search_services_by_public_id(query)
      service = Service.find_by_public_id(query)
      return [] unless service

      [format_service(service)]
    end

    def search_services(query)
      services = Service.where("name ILIKE :q", q: "%#{query}%").limit(5)
      services.map { |s| format_service(s) }
    end

    def search_domains_by_public_id(query)
      domain = Phish::Domain.find_by_public_id(query)
      return [] unless domain

      [format_domain(domain)]
    end

    def search_domains(query)
      domains = Phish::Domain.where("domain ILIKE :q", q: "%#{query}%").limit(5)
      domains.map { |d| format_domain(d) }
    end

    def search_urls_by_public_id(query)
      url = Phish::Url.find_by_public_id(query)
      return [] unless url

      [format_url(url)]
    end

    def search_urls(query)
      urls = Phish::Url.where("url ILIKE :q", q: "%#{query}%").limit(5)
      urls.map { |u| format_url(u) }
    end

    def format_user(user)
      {
        type: "user",
        section: "Users",
        icon: "👤",
        name: user.full_name,
        subtitle: "#{user.email} • #{user.pd_id}",
        url: admin_user_path(user),
        badge: user.access_level,
        badge_color: user_badge_color(user)
      }
    end

    def format_service(service)
      {
        type: "service",
        section: "Services",
        icon: "⚙️",
        name: service.name,
        subtitle: "#{service.service_keys.count} keys • #{service.status}",
        url: admin_service_path(service),
        badge: service.status,
        badge_color: service.active? ? "emerald" : "amber"
      }
    end

    def format_domain(domain)
      {
        type: "domain",
        section: "Domains",
        icon: "🌐",
        name: domain.domain,
        subtitle: domain.verdict&.classification || "unchecked",
        url: admin_domain_path(domain),
        badge: domain.verdict&.classification || "unknown",
        badge_color: verdict_badge_color(domain.verdict&.classification)
      }
    end

    def format_url(url)
      {
        type: "url",
        section: "URLs",
        icon: "🔗",
        name: url.url.truncate(60),
        subtitle: url.verdict&.classification || "unchecked",
        url: admin_url_path(url),
        badge: url.verdict&.classification || "unknown",
        badge_color: verdict_badge_color(url.verdict&.classification)
      }
    end

    def user_badge_color(user)
      case user.access_level
      when "owner" then "purple"
      when "superadmin" then "red"
      when "admin" then "amber"
      when "trusted" then "cyan"
      else "slate"
      end
    end

    def verdict_badge_color(classification)
      case classification
      when "phishing" then "red"
      when "suspicious" then "amber"
      when "clean" then "emerald"
      else "slate"
      end
    end
  end
end
