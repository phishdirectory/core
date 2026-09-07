# frozen_string_literal: true

# The public XARF utility.
#
# Anyone can paste a link and get a XARF v4 report back. Sending that report to
# the registrar and hosting provider needs an account, because that path puts
# mail in someone else's inbox under our name.
class XarfController < ApplicationController
  before_action :authenticate_user!, only: :submit

  # Why the report could not be sent on the reporter's behalf. The messages for
  # why there is no report at all live on the result itself, so the page and
  # the flash say the same thing.
  SUBMIT_DECLINED = {
    not_phishing: "We only send reports for confirmed phishing. " \
                  "You can still download the report and send it yourself.",
    low_confidence: "Our confidence in this verdict is below the threshold for " \
                    "sending a report automatically. You can still download it " \
                    "and send it yourself.",
    reporting_disabled: "Automatic reporting is paused right now. " \
                        "Download the report and send it yourself, or try again later."
  }.freeze

  def new
    @result = nil
    render :new
  end

  def create
    @result = build_report
    render :new
  end

  def download
    @result = build_report

    unless @result.reportable?
      redirect_to xarf_path, alert: @result.message
      return
    end

    send_data "#{@result.json}\n",
              filename: @result.filename,
              type: "application/json",
              disposition: "attachment"
  end

  def submit
    @result = build_report

    unless @result.reportable?
      flash.now[:alert] = @result.message
      return render :new
    end

    creator = Report::CaseCreationService.new(@result.record, @result.verdict)

    case creator.decline_reason
    when nil
      @submitted_case = creator.create_case!
      flash.now[:notice] = "Report sent. We are notifying the registrar and hosting provider."
    when :existing_case
      # Not a failure. Someone already reported this, and saying so is more
      # useful than silently doing nothing.
      @submitted_case = creator.existing_case
      flash.now[:notice] = "This is already reported. We opened a case for it earlier."
    else
      flash.now[:alert] = SUBMIT_DECLINED.fetch(creator.decline_reason)
    end

    render :new
  end

  private

  def build_report
    Xarf::PublicReportService.call(type: params[:type], input: params[:value])
  end
end
