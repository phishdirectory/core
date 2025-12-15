# frozen_string_literal: true

module Admin
  class ImpersonationController < BaseController
    skip_before_action :require_admin!

    def destroy
      if impersonating?
        stop_impersonating!
        redirect_to admin_root_path, notice: "Stopped impersonating. Welcome back!"
      else
        redirect_to root_path, alert: "You are not impersonating anyone."
      end
    end
  end
end
