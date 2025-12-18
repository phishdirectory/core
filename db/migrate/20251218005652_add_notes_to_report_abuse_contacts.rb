class AddNotesToReportAbuseContacts < ActiveRecord::Migration[8.1]
  def change
    add_column :report_abuse_contacts, :notes, :text
  end
end
