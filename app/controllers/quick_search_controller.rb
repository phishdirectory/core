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
      { id: "nav-check-phone", name: "Check Phone Number", section: "Navigation", icon: "📞", url: dashboard_phone_check_path, keywords: "phone number scam verify" },
      { id: "nav-check-email", name: "Check Email", section: "Navigation", icon: "📧", url: dashboard_email_check_path, keywords: "email address fraud verify" },
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
      { id: "admin-phones", name: "Phone Numbers", section: "Admin", icon: "📞", url: admin_phone_numbers_path, keywords: "phones numbers scam voip" },
      { id: "admin-emails", name: "Emails", section: "Admin", icon: "📧", url: admin_emails_path, keywords: "emails fraud disposable" },
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
    when /^phn_/i
      results += search_phone_numbers_by_public_id(query)
    when /^eml_/i
      results += search_emails_by_public_id(query)
    when /^PDU/i
      results += search_users_by_pd_id(query) if current_user.admin?
    else
      # General search across relevant types
      results += search_domains(query)
      results += search_urls(query)
      results += search_phone_numbers(query)
      results += search_emails(query)
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

  def search_phone_numbers_by_public_id(query)
    phone = Phish::PhoneNumber.find_by_public_id(query)
    return [] unless phone

    [format_phone_number(phone)]
  end

  def search_phone_numbers(query)
    phone_numbers = Phish::PhoneNumber.where("phone_number ILIKE :q", q: "%#{query}%").limit(5)
    phone_numbers.map { |p| format_phone_number(p) }
  end

  def search_emails_by_public_id(query)
    email = Phish::Email.find_by_public_id(query)
    return [] unless email

    [format_email(email)]
  end

  def search_emails(query)
    emails = Phish::Email.where("email ILIKE :q", q: "%#{query}%").limit(5)
    emails.map { |e| format_email(e) }
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

  def format_phone_number(phone)
    {
      type: "phone",
      section: "Phone Numbers",
      icon: "📞",
      name: phone.phone_number,
      subtitle: phone.verdict&.classification || "unchecked",
      url: current_user.admin? ? admin_phone_number_path(phone) : "#",
      badge: phone.verdict&.classification || "unknown",
      badge_color: verdict_badge_color(phone.verdict&.classification)
    }
  end

  def format_email(email)
    {
      type: "email",
      section: "Emails",
      icon: "📧",
      name: email.email,
      subtitle: email.verdict&.classification || "unchecked",
      url: current_user.admin? ? admin_email_path(email) : "#",
      badge: email.verdict&.classification || "unknown",
      badge_color: verdict_badge_color(email.verdict&.classification)
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
