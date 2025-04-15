# frozen_string_literal: true

require "rails_helper"

RSpec.describe MagicLinkMailer, type: :mailer do
  describe "login_link" do
    let(:mail) { described_class.login_link }

    it "renders the subject" do
      expect(mail.subject).to eq("Login link")
    end

    it "renders the to address" do
      expect(mail.to).to eq(["to@example.org"])
    end

    it "renders the from address" do
      expect(mail.from).to eq(["from@example.com"])
    end

    it "renders the body" do
      expect(mail.body.encoded).to match("Hi")
    end
  end

end
