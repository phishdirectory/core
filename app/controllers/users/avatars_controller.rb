# frozen_string_literal: true

module Users
  class AvatarsController < ApplicationController
    skip_before_action :authenticate_user!, raise: false

    # GET /u/:pd_id/avatar
    # GET /u/:pd_id/avatar/:variant
    def show
      user = User.find_by!(pd_id: params[:pd_id])
      variant = (params[:variant] || "thumb").to_sym

      if user.has_profile_photo?
        redirect_to rails_blob_url(user.profile_photo_url(variant: variant)), allow_other_host: true
      else
        render_initials_avatar(user, variant)
      end
    end

    # GET /u/:pd_id/initials
    # GET /u/:pd_id/initials/:variant
    def initials
      user = User.find_by!(pd_id: params[:pd_id])
      variant = (params[:variant] || "thumb").to_sym

      render_initials_avatar(user, variant)
    end

    private

    def render_initials_avatar(user, variant)
      size = variant_size(variant)
      svg = InitialsAvatarService.generate(user.initials, size: size)

      # Cache for 1 hour
      expires_in 1.hour, public: true

      render inline: svg, content_type: "image/svg+xml"
    end

    def variant_size(variant)
      case variant.to_sym
      when :thumb then 100
      when :medium then 200
      when :large then 400
      else 100
      end
    end
  end
end
