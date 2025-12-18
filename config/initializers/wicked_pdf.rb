# frozen_string_literal: true

WickedPdf.config = {
  exe_path: Gem.bin_path("wkhtmltopdf-binary", "wkhtmltopdf"),
  enable_local_file_access: true
}
