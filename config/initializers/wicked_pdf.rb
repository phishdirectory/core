# frozen_string_literal: true

WickedPdf.configure do |config|
  config.exe_path = Gem.bin_path("wkhtmltopdf-binary", "wkhtmltopdf")
  config.enable_local_file_access = true
end
