# frozen_string_literal: true

namespace :report do
  desc "Backfill missing verdict snapshots for report cases"
  task backfill_verdicts: :environment do
    puts "Finding cases with missing verdict snapshots..."

    cases_fixed = 0
    cases_skipped = 0

    Report::Case.find_each do |report_case|
      # Skip if already has a valid verdict snapshot
      if report_case.verdict_snapshot.present?
        cases_skipped += 1
        next
      end

      # Get the reportable (domain or URL) and its verdict
      reportable = report_case.reportable
      unless reportable
        puts "  [SKIP] Case #{report_case.case_number}: reportable not found"
        cases_skipped += 1
        next
      end

      verdict = reportable.verdict
      unless verdict
        puts "  [SKIP] Case #{report_case.case_number}: reportable has no verdict"
        cases_skipped += 1
        next
      end

      # Create verdict snapshot from current verdict
      snapshot = Verdict.create!(
        classification: verdict.classification || "phishing",
        confidence_score: verdict.confidence_score || report_case.confidence_at_creation,
        sources: verdict.sources || [],
        metadata: (verdict.metadata || {}).merge(
          backfilled: true,
          backfilled_at: Time.current.iso8601,
          original_verdict_id: verdict.id
        )
      )

      report_case.update!(verdict_snapshot: snapshot)

      puts "  [FIXED] Case #{report_case.case_number}: created verdict snapshot from #{reportable.class.name}"
      cases_fixed += 1
    end

    puts "\nDone! Fixed: #{cases_fixed}, Skipped: #{cases_skipped}"
  end

  desc "Backfill missing payload data for report submissions"
  task backfill_payloads: :environment do
    puts "Finding submissions with missing payloads..."

    submissions_fixed = 0
    submissions_skipped = 0

    Report::Submission.find_each do |submission|
      # Skip if already has payload
      if submission.payload.present? && submission.payload.keys.any?
        submissions_skipped += 1
        next
      end

      # Build payload from case data
      payload = submission.build_payload

      if payload[:domain].blank? && payload[:classification].blank?
        puts "  [SKIP] Submission #{submission.public_id}: could not build payload"
        submissions_skipped += 1
        next
      end

      submission.update!(payload: payload)
      puts "  [FIXED] Submission #{submission.public_id}: populated payload"
      submissions_fixed += 1
    end

    puts "\nDone! Fixed: #{submissions_fixed}, Skipped: #{submissions_skipped}"
  end

  desc "Run all report data backfills"
  task backfill_all: [:backfill_verdicts, :backfill_payloads] do
    puts "\nAll backfills complete!"
  end
end
