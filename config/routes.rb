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

    # Email preview (development only)
    mount LetterOpenerWeb::Engine => "/admin/mail" if Rails.env.development?
  end

  # ===========================================
  # Authentication Routes
  # ===========================================
  scope :auth do
    get "login", to: "auth#login", as: :login
    post "login", to: "auth#send_magic_link"
    get "magic_link/:token", to: "auth#magic_link_login", as: :magic_link_login
    delete "logout", to: "auth#logout", as: :logout
    get "me", to: "auth#me", as: :auth_me
  end

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

  # ===========================================
  # Dashboard Routes
  # ===========================================
  namespace :dashboard do
    root to: "dashboard#index"

    resources :api_keys, only: [:index, :create, :destroy] do
      member do
        post :regenerate
      end
    end

    resource :profile, only: [:show, :edit, :update]
    resources :sessions, only: [:index, :destroy]
  end

  # ===========================================
  # Admin Routes
  # ===========================================
  namespace :admin do
    root to: "dashboard#index"

    resources :users do
      member do
        post :impersonate
        post :suspend
        post :reactivate
        post :lock
        post :unlock
        post :make_admin
        post :remove_privileges
      end
      collection do
        get :search
      end
    end

    resources :services do
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
      end

      # URL checking
      namespace :url do
        get "check", to: "urls#check"
        post "check", to: "urls#check"
        get "bulk", to: "urls#bulk"
        post "bulk", to: "urls#bulk"
      end

      # Webhooks
      resources :webhooks, only: [:index, :create, :destroy]
    end
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
