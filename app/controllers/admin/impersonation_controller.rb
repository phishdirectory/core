# frozen_string_literal: true

module Admin
  class ImpersonationController < BaseController
    skip_before_action :require_admin!
    before_action :require_impersonating!

    def destroy
      stop_impersonating!
      redirect_to admin_root_path, notice: "Stopped impersonating. Welcome back!"
    end

    private

    def require_impersonating!
      unless impersonating?
        redirect_to root_path, alert: "You are not impersonating anyone."
      end
    end
  end
end
