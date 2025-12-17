# frozen_string_literal: true

class QuickSearchController < ApplicationController
  before_action :authenticate_user!

  # GET /quick_search
  # Returns JSON with navigation actions and search results
  def index
    query = params[:q].to_s.strip

    render json: {
      navigation: navigation_actions,
      admin_navigation: current_user.admin? ? admin_navigation_actions : [],
      results: query.present? ? search_results(query) : []
    }
  end

  private

  def navigation_actions
    [
      { id: "nav-dashboard", name: "Dashboard", section: "Navigation", icon: "🏠", url: dashboard_root_path, keywords: "home main" },
      { id: "nav-profile", name: "Profile Settings", section: "Navigation", icon: "👤", url: dashboard_profile_path, keywords: "account settings user" },
      { id: "nav-api-keys", name: "API Keys", section: "Navigation", icon: "🔑", url: dashboard_api_keys_path, keywords: "keys tokens auth" },
      { id: "nav-sessions", name: "Active Sessions", section: "Navigation", icon: "💻", url: dashboard_sessions_path, keywords: "devices login" },
      { id: "nav-check", name: "Check Domain/URL", section: "Navigation", icon: "🔍", url: dashboard_domain_check_path, keywords: "scan phishing verify" },
      { id: "nav-docs", name: "API Documentation", section: "Navigation", icon: "📚", url: docs_path, keywords: "api reference help" },
      { id: "nav-logout", name: "Sign Out", section: "Navigation", icon: "🚪", url: logout_path, keywords: "exit logout signout", method: "delete" }
    ]
  end

  def admin_navigation_actions
    [
      { id: "admin-dashboard", name: "Admin Dashboard", section: "Admin", icon: "⚡", url: admin_root_path, keywords: "admin panel" },
      { id: "admin-users", name: "Manage Users", section: "Admin", icon: "👥", url: admin_users_path, keywords: "users accounts" },
      { id: "admin-services", name: "Manage Services", section: "Admin", icon: "⚙️", url: admin_services_path, keywords: "services api clients" },
      { id: "admin-domains", name: "Phishing Domains", section: "Admin", icon: "🌐", url: admin_domains_path, keywords: "domains phishing" },
      { id: "admin-urls", name: "Phishing URLs", section: "Admin", icon: "🔗", url: admin_urls_path, keywords: "urls phishing links" },
      { id: "admin-flipper", name: "Feature Flags", section: "Admin Tools", icon: "🚩", url: "/admin/flipper", keywords: "flags features toggle" },
      { id: "admin-jobs", name: "Background Jobs", section: "Admin Tools", icon: "⏱️", url: "/admin/jobs", keywords: "jobs queue workers sidekiq" },
      { id: "admin-blazer", name: "Analytics (Blazer)", section: "Admin Tools", icon: "📊", url: "/admin/blazer", keywords: "analytics sql queries reports" },
      { id: "admin-pghero", name: "Database (PgHero)", section: "Admin Tools", icon: "🗄️", url: "/admin/pghero", keywords: "database postgres performance" },
      { id: "admin-console", name: "Console Audits", section: "Admin Tools", icon: "📝", url: "/admin/console_audits", keywords: "console logs audit" }
    ]
  end

  def search_results(query)
    results = []

    # Search by prefix to determine type
    case query
    when /^usr_/i
      results += search_users_by_public_id(query)
    when /^svc_/i
      results += search_services_by_public_id(query) if current_user.admin?
    when /^dom_/i
      results += search_domains_by_public_id(query)
    when /^url_/i
      results += search_urls_by_public_id(query)
    when /^PDU/i
      results += search_users_by_pd_id(query) if current_user.admin?
    else
      # General search across relevant types
      results += search_domains(query)
      results += search_urls(query)
      results += search_users(query) if current_user.admin?
      results += search_services(query) if current_user.admin?
    end

    results.first(10)
  end

  def search_users_by_public_id(query)
    return [] unless current_user.admin?

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
      url: current_user.admin? ? admin_user_path(user) : "#",
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
      url: current_user.admin? ? admin_domain_path(domain) : "#",
      badge: domain.verdict&.classification || "unknown",
      badge_color: verdict_badge_color(domain.verdict&.classification)
    }
  end

  def format_url(url)
    {
      type: "url",
      section: "URLs",
      icon: "🔗",
      name: url.url.truncate(50),
      subtitle: url.verdict&.classification || "unchecked",
      url: current_user.admin? ? admin_url_path(url) : "#",
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
