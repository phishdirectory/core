# frozen_string_literal: true

require "admin_constraint"

Rails.application.routes.draw do
  # ===========================================
  # Health Checks
  # ===========================================
  get "up" => "rails/health#show", as: :rails_health_check

  # OkComputer health checks mounted at /health
  mount OkComputer::Engine, at: "/health"

  # ===========================================
  # OAuth 2.0 (Doorkeeper)
  # ===========================================
  use_doorkeeper do
    # Customize Doorkeeper routes if needed
    skip_controllers :applications, :authorized_applications
  end

  # OpenID Connect UserInfo endpoint
  get "/oauth/userinfo", to: "oauth/userinfo#show"

  # ===========================================
  # Development Tools (unauthenticated)
  # ===========================================
  if Rails.env.development?
    mount LetterOpenerWeb::Engine, at: "/letter_opener"
  end

  # ===========================================
  # Admin Engines (protected by AdminConstraint)
  # ===========================================
  constraints AdminConstraint.new(minimum_level: :admin) do
    # Feature flags UI
    mount Flipper::UI.app(Flipper) => "/admin/flipper"

    # Background jobs dashboard
    mount MissionControl::Jobs::Engine => "/admin/jobs"

    # BI dashboards
    mount Blazer::Engine => "/admin/blazer"

    # Console audit UI
    mount Audits1984::Engine => "/admin/console_audits"

    # PostgreSQL monitoring
    mount PgHero::Engine => "/admin/pghero"
  end

  # ===========================================
  # Global Quick Search (Command-K)
  # ===========================================
  get "quick_search", to: "quick_search#index"

  # ===========================================
  # Authentication Routes
  # ===========================================
  scope :auth do
    get "login", to: "auth#login", as: :login
    post "login", to: "auth#send_magic_link"
    post "password_login", to: "auth#password_login", as: :password_login
    get "magic_link/:token", to: "auth#magic_link_login", as: :magic_link_login
    delete "logout", to: "auth#logout", as: :logout
    get "me", to: "auth#me", as: :auth_me

    # Password reset
    get "password/forgot", to: "auth/passwords#new", as: :forgot_password
    post "password/forgot", to: "auth/passwords#create"
    get "password/reset/:token", to: "auth/passwords#edit", as: :reset_password
    patch "password/reset/:token", to: "auth/passwords#update"

    # Email confirmation
    get "confirm/:token", to: "auth/confirmations#show", as: :confirm_email
    post "confirm/resend", to: "auth/confirmations#create", as: :resend_confirmation
  end

  # ===========================================
  # Documentation
  # ===========================================
  # Mount rswag BEFORE the catch-all docs/:page route
  mount Rswag::Ui::Engine => "/docs/api"
  mount Rswag::Api::Engine => "/api-docs"
  get "docs", to: "docs#index", as: :docs
  get "docs/:page", to: "docs#show", as: :docs_page

  # ===========================================
  # User Routes
  # ===========================================
  get "signup", to: "users#new", as: :signup
  post "signup", to: "users#create"

  resources :users, only: [:show, :edit, :update] do
    member do
      get :sessions
    end
  end

  # Public avatar URLs
  scope "/u/:pd_id", constraints: { pd_id: /PDU\d[a-zA-Z0-9]{7}/ } do
    get "avatar", to: "users/avatars#show", as: :user_avatar
    get "avatar/:variant", to: "users/avatars#show"
    get "initials", to: "users/avatars#initials", as: :user_initials
    get "initials/:variant", to: "users/avatars#initials"
  end

  # ===========================================
  # Dashboard Routes
  # ===========================================
  namespace :dashboard do
    root to: "dashboard#index"

    # Domain checking
    get "check", to: "domain_checks#new", as: :domain_check
    post "check", to: "domain_checks#create"

    # Phone number checking
    get "check_phone", to: "phone_checks#new", as: :phone_check
    post "check_phone", to: "phone_checks#create"

    # Email checking
    get "check_email", to: "email_checks#new", as: :email_check
    post "check_email", to: "email_checks#create"

    resources :api_keys, only: [:index, :create, :destroy] do
      member do
        post :regenerate
      end
    end

    resource :profile, only: [:show, :edit, :update]
    resources :sessions, only: [:index, :destroy]

    # Scam classification (trusted+ users only)
    get "classifications", to: "classifications#index", as: :classifications
    get "classifications/:type/:id", to: "classifications#show", as: :classification
    post "classifications/:type/:id", to: "classifications#create", as: :create_classification
    post "classifications/:type/:id/mark_clean", to: "classifications#mark_clean", as: :mark_clean_classification
    post "classifications/:type/:id/skip", to: "classifications#skip", as: :skip_classification
  end

  # ===========================================
  # Admin Routes
  # ===========================================
  namespace :admin do
    root to: "dashboard#index"

    # Command-K quick search
    get "quick_search", to: "quick_search#index"

    resources :users do
      member do
        post :impersonate
        post :suspend
        post :reactivate
        post :lock
        post :unlock
        post :make_admin
        post :remove_privileges
        post :add_service_role
        delete "service_roles/:role_id", action: :remove_service_role, as: :remove_service_role
      end
      collection do
        get :search
      end
    end

    resources :services do
      member do
        post :suspend
        post :reactivate
        post :decommission
      end
      resources :keys, controller: "service_keys", only: [:index, :create, :destroy] do
        member do
          post :deprecate
          post :revoke
        end
      end
      resources :webhooks, controller: "service_webhooks", only: [:index, :create, :destroy]
    end

    resources :domains, controller: "phish_domains", only: [:index, :show]
    resources :urls, controller: "phish_urls", only: [:index, :show]
    resources :phone_numbers, controller: "phish_phone_numbers", only: [:index, :show]
    resources :emails, controller: "phish_emails", only: [:index, :show]
    resources :verdicts, only: [:index, :show, :edit, :update]
    resources :protections, only: [:index, :show, :new, :create, :destroy]

    # Monitoring
    resources :api_requests, only: [:index, :show]
    resources :webhook_deliveries, only: [:index, :show] do
      member do
        post :retry
      end
    end

    # Report/Abuse system
    namespace :report do
      resources :abuse_contacts do
        collection do
          get :import
          post :import, action: :perform_import
        end
      end
      resources :cases, only: [:index, :show] do
        member do
          post :retry_submission
          post :escalate
          post :resolve
        end
      end
    end

    # SAML Service Providers
    namespace :saml do
      resources :service_providers do
        member do
          post :enable
          post :disable
        end
      end
      resources :authentications, only: [:index, :show]
    end

    # Stop impersonation
    delete "stop_impersonating", to: "impersonation#destroy", as: :stop_impersonating
  end

  # ===========================================
  # API Routes (v1)
  # ===========================================
  namespace :api do
    namespace :v1 do
      # Health check
      get "health", to: "health#show"

      # Authentication
      namespace :auth do
        post "authenticate", to: "auth#authenticate"  # Service-to-service auth
        post "token", to: "auth#token"                # Get access token
        post "refresh", to: "auth#refresh"            # Refresh token
      end

      # Current user
      namespace :user do
        get "me", to: "users#me"
        put "me", to: "users#update"
      end

      # Domain checking
      namespace :domain do
        get "check", to: "domains#check"
        post "check", to: "domains#check"
        get "bulk", to: "domains#bulk"
        post "bulk", to: "domains#bulk"

        # WHOIS/RDAP registration info
        get "whois", to: "whois#check"
        post "whois", to: "whois#check"
        get "whois/bulk", to: "whois#bulk"
        post "whois/bulk", to: "whois#bulk"

        resources :protections, only: [:index, :show, :create, :destroy]
      end

      # URL checking
      namespace :url do
        get "check", to: "urls#check"
        post "check", to: "urls#check"
        get "bulk", to: "urls#bulk"
        post "bulk", to: "urls#bulk"
      end

      # Phone number checking
      namespace :phone do
        get "check", to: "phone_numbers#check"
        post "check", to: "phone_numbers#check"
        get "bulk", to: "phone_numbers#bulk"
        post "bulk", to: "phone_numbers#bulk"
      end

      # Email checking
      namespace :email do
        get "check", to: "emails#check"
        post "check", to: "emails#check"
        get "bulk", to: "emails#bulk"
        post "bulk", to: "emails#bulk"
      end

      # Webhooks
      resources :webhooks, only: [:index, :create, :destroy]

      # Identity API (service-to-service user management)
      namespace :identity do
        resources :users, only: [:show, :create, :update] do
          collection do
            get :by_email
          end
        end
        post "authenticate", to: "auth#authenticate"
      end
    end
  end

  # ===========================================
  # SAML Identity Provider
  # ===========================================
  namespace :saml do
    get  "metadata", to: "idp#metadata"
    get  "auth",     to: "idp#new"
    post "auth",     to: "idp#create"
    post "logout",   to: "idp#logout"
  end

  # ===========================================
  # Root Route
  # ===========================================
  root to: "home#index"

  # ===========================================
  # Catch-all for 404s (must be last)
  # ===========================================
  # match "*path", to: "errors#not_found", via: :all
end
