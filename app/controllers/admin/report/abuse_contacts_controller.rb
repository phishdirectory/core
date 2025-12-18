# frozen_string_literal: true

module Admin
  module Report
    class AbuseContactsController < Admin::BaseController
      before_action :set_abuse_contact, only: [:show, :edit, :update, :destroy]

      def index
        @abuse_contacts = ::Report::AbuseContact
          .order(priority: :asc, name: :asc)
          .page(params[:page])

        # Filter by type if specified
        if params[:type].present?
          @abuse_contacts = @abuse_contacts.where(contact_type: params[:type])
        end

        # Filter by active status
        if params[:active].present?
          @abuse_contacts = @abuse_contacts.where(active: params[:active] == "true")
        end

        # Search by name
        if params[:q].present?
          @abuse_contacts = @abuse_contacts.where("name ILIKE ?", "%#{params[:q]}%")
        end
      end

      def show
        @submissions = @abuse_contact.submissions.order(created_at: :desc).limit(20)
      end

      def new
        @abuse_contact = ::Report::AbuseContact.new
      end

      def create
        @abuse_contact = ::Report::AbuseContact.new(abuse_contact_params)

        if @abuse_contact.save
          redirect_to admin_report_abuse_contact_path(@abuse_contact),
                      notice: "Abuse contact created successfully."
        else
          render :new, status: :unprocessable_entity
        end
      end

      def edit
      end

      def update
        if @abuse_contact.update(abuse_contact_params)
          redirect_to admin_report_abuse_contact_path(@abuse_contact),
                      notice: "Abuse contact updated successfully."
        else
          render :edit, status: :unprocessable_entity
        end
      end

      def destroy
        @abuse_contact.discard

        redirect_to admin_report_abuse_contacts_path,
                    notice: "Abuse contact removed."
      end

      # GET /admin/report/abuse_contacts/import
      def import
        @import_stats = nil
      end

      # POST /admin/report/abuse_contacts/import
      def perform_import
        if params[:file].blank?
          redirect_to import_admin_report_abuse_contacts_path,
                      alert: "Please select a CSV file to import."
          return
        end

        importer = ::Report::AbuseContactImporter.new(params[:file])
        @import_stats = importer.import!

        flash.now[:notice] = "Import complete: #{@import_stats[:created]} created, #{@import_stats[:updated]} updated."

        if @import_stats[:errors].any?
          flash.now[:alert] = "#{@import_stats[:errors].length} errors occurred during import."
        end

        render :import
      end

      private

      def set_abuse_contact
        @abuse_contact = ::Report::AbuseContact.find_by_public_id!(params[:id])
      end

      def abuse_contact_params
        params.require(:report_abuse_contact).permit(
          :name,
          :contact_type,
          :method,
          :email,
          :web_form_url,
          :organization,
          :trusted_reporter,
          :accepts_bulk,
          :priority,
          :active,
          :notes,
          web_form_fields: {},
          registrar_patterns: [],
          nameserver_patterns: [],
          ip_ranges: []
        )
      end
    end
  end
end
