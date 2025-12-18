# frozen_string_literal: true

# Seed data for Report::AbuseContact
# Sources: registrars, hosting providers, link shorteners, and other services
#
# Run with: bin/rails db:seed

module Seeds
  class AbuseContacts
    CONTACTS = [
      # Registrars (priority: 10)
      { name: "1API", contact_type: :registrar, method: :email, email: "abuse@1api.net", priority: 10 },
      { name: "Alibaba Cloud", contact_type: :registrar, method: :email, email: "infosec@service.aliyun.com", priority: 10 },
      { name: "Cloudflare", contact_type: :registrar, method: :web_form, web_form_url: "https://abuse.cloudflare.com/", priority: 10, notes: "The abuse@cloudflare.com email will not work and will redirect you to the form." },
      { name: "Communigal Communications", contact_type: :registrar, method: :email, email: "abuse@galcomm.com", priority: 10 },
      { name: "Cosmotown", contact_type: :registrar, method: :email, email: "abuse@cosmotown.com", priority: 10 },
      { name: "Eranet International Limited", contact_type: :registrar, method: :email, email: "support@tnet.hk", priority: 10 },
      { name: "GMO Internet Inc.d/b/a Onamae.com", contact_type: :registrar, method: :email, email: "abuse@gmo.jp", priority: 10 },
      { name: "GNAME", contact_type: :registrar, method: :web_form, web_form_url: "https://www.gname.com/abuse", priority: 10, notes: "If your complaint gets denied, email complaint@gname.com." },
      { name: "GoDaddy", contact_type: :registrar, method: :web_form, web_form_url: "https://supportcenter.godaddy.com/AbuseReport", priority: 10 },
      { name: "Host Arabia", contact_type: :registrar, method: :email, email: "dom@tasjeel.ae", priority: 10 },
      { name: "Hostinger", contact_type: :registrar, method: :web_form, email: "abuse@hostinger.com", web_form_url: "https://www.hostinger.com/report-abuse", priority: 10 },
      { name: "Kouming", contact_type: :registrar, method: :email, email: "abuse@kouming.com", priority: 10 },
      { name: "MarkMonitor Inc", contact_type: :registrar, method: :email, email: "abusecomplaints@markmonitor.com", priority: 10 },
      { name: "Metaregistrar BV", contact_type: :registrar, method: :email, email: "abuse@metaregistrar.com", priority: 10 },
      { name: "NameSilo", contact_type: :registrar, method: :web_form, web_form_url: "https://new.namesilo.com/phishing_report.php", priority: 10 },
      { name: "NiceNIC.NET", contact_type: :registrar, method: :web_form, email: "abuse@nicenic.net", web_form_url: "https://nicenic.net/customer/reportabuse.php", priority: 10, notes: "Use the form for faster response. Use an alt email when contacting." },
      { name: "OwnRegistrar", contact_type: :registrar, method: :email, email: "abuse@ownregistrar.com", priority: 10 },
      { name: "Porkbun", contact_type: :registrar, method: :web_form, web_form_url: "https://porkbun.com/abuse", priority: 10 },
      { name: "REG.RU", contact_type: :registrar, method: :email, email: "abuse@reg.ru", priority: 10, notes: "Due to Russian laws, also contact incident@cert.gov.ru who will instruct reg.ru to suspend the domain." },
      { name: "RU-CENTER", contact_type: :registrar, method: :email, email: "tld-abuse@nic.ru", priority: 10 },
      { name: "Registrar.eu", contact_type: :registrar, method: :web_form, email: "support@openprovider.zendesk.com", web_form_url: "https://abuse.registrar.eu/", priority: 10 },
      { name: "Regtons", contact_type: :registrar, method: :email, email: "abuse@regtons.com", priority: 10 },
      { name: "Rumahweb Indonesia", contact_type: :registrar, method: :email, email: "abuse@rumahweb.co.id", priority: 10 },
      { name: "Sav.com, LLC", contact_type: :registrar, method: :web_form, email: "abuse-contact@sav.com", web_form_url: "https://abuse.sav.com/", priority: 10, notes: "The email will not work, use the form." },
      { name: "Tucows", contact_type: :registrar, method: :web_form, web_form_url: "https://tucowsdomains.com/report-abuse/", priority: 10 },
      { name: "webnic.cc", contact_type: :registrar, method: :email, email: "compliance_abuse@webnic.cc", priority: 10 },

      # Hosting Providers (priority: 30)
      { name: "Amazon AWS", contact_type: :hosting, method: :email, email: "abuse@amazonaws.com", priority: 30 },
      { name: "Deno Deploy", contact_type: :hosting, method: :email, email: "deploy@deno.com", priority: 30, notes: "Handles deno.dev domains." },
      { name: "ESITED", contact_type: :hosting, method: :email, email: "net-abuse@esited.com", priority: 30 },
      { name: "Google Cloud", contact_type: :hosting, method: :email, email: "google-cloud-compliance@google.com", priority: 30 },
      { name: "IQWeb FZ-LLC", contact_type: :hosting, method: :email, email: "abuse@iqweb.io", priority: 30 },
      { name: "MTW-AS (RU)", contact_type: :hosting, method: :email, email: "support@ruvds.com", priority: 30 },
      { name: "ROUTERHOSTING / Cloudzy", contact_type: :hosting, method: :email, email: "abuse-reports@cloudzy.com", priority: 30 },
      { name: "SEDO-AS (DE)", contact_type: :hosting, method: :email, email: "ripe@internetx.de", priority: 30 },
      { name: "TRELLIAN-AS-AP", contact_type: :hosting, method: :email, email: "abuse@trellian.com", priority: 30 },
      { name: "Vercel", contact_type: :hosting, method: :web_form, email: "abuse@vercel.com", web_form_url: "https://vercel.com/abuse", priority: 30 },
      { name: "ZhouyiSat Communications", contact_type: :hosting, method: :email, email: "support@62yun.com", priority: 30 },
      { name: "000webhost.com", contact_type: :hosting, method: :web_form, web_form_url: "https://www.000webhost.com/report-abuse", priority: 30 },

      # Link Shorteners (priority: 50)
      { name: "bit.ly", contact_type: :other, method: :web_form, web_form_url: "https://bitly.com/pages/trust/report-abuse", priority: 50 },
      { name: "tinyurl.com", contact_type: :other, method: :email, email: "abuse@tinyurl.com", priority: 50 },
      { name: "t.ly", contact_type: :other, method: :email, email: "support@t.ly", priority: 50 },
      { name: "rb.gy", contact_type: :other, method: :email, email: "support@rebrandly.com", priority: 50 },
      { name: "short.gy", contact_type: :other, method: :email, email: "abuse@short.io", priority: 50 },
      { name: "is.gd", contact_type: :other, method: :web_form, email: "abuse@is.gd", web_form_url: "https://is.gd/contact.php", priority: 50 },
      { name: "tiny.cc", contact_type: :other, method: :web_form, web_form_url: "https://tiny.cc/contact", priority: 50 },
      { name: "gg.gg", contact_type: :other, method: :web_form, web_form_url: "https://gg.gg/abuse", priority: 50 },
      { name: "shorturl.at", contact_type: :other, method: :web_form, web_form_url: "https://www.shorturl.at/report-malicious-url.php", priority: 50 },
      { name: "clck.ru", contact_type: :other, method: :email, email: "abuse@yandex.ru", priority: 50 },
      { name: "x.co", contact_type: :other, method: :web_form, web_form_url: "https://supportcenter.godaddy.com/AbuseReport/", priority: 50 },
      { name: "urlz.fr", contact_type: :other, method: :web_form, web_form_url: "https://urlz.fr/contact.php#abuse", priority: 50 },
      { name: "kurl.ru", contact_type: :other, method: :web_form, web_form_url: "https://kurl.ru/report", priority: 50 },
      { name: "7ink.ru", contact_type: :other, method: :web_form, web_form_url: "https://7ink.ru/report", priority: 50 },
      { name: "u.to", contact_type: :other, method: :web_form, web_form_url: "https://u.to/", priority: 50, notes: "Select the option that says 'Фишинг' (phishing content in Russian)." },
      { name: "n9.cl", contact_type: :other, method: :web_form, web_form_url: "https://n9.cl/en/n", priority: 50 },
      { name: "shorter.me", contact_type: :other, method: :web_form, web_form_url: "https://shorter.me/page/report-short-url", priority: 50 },
      { name: "go-link.ru", contact_type: :other, method: :web_form, web_form_url: "https://go-link.ru/callback", priority: 50 },
      { name: "surl.li", contact_type: :other, method: :email, email: "tools@hyperhost.ua", priority: 50 },
      { name: "e.vg", contact_type: :other, method: :web_form, web_form_url: "https://www.e.vg/report", priority: 50 },
      { name: "dub.sh", contact_type: :other, method: :web_form, web_form_url: "https://dub.co/legal/abuse", priority: 50 },
      { name: "snl.ink", contact_type: :other, method: :web_form, web_form_url: "https://snick.link/report", priority: 50 },
      { name: "snick.link", contact_type: :other, method: :web_form, web_form_url: "https://snick.link/report", priority: 50 },
      { name: "Cutt.ly", contact_type: :other, method: :web_form, web_form_url: "https://cutt.ly/report", priority: 50 },

      # Other Services (priority: 50)
      { name: "Discord", contact_type: :other, method: :web_form, web_form_url: "https://support.discord.com/hc/en-us/requests/new?ticket_form_id=12275528604823", priority: 50, notes: "EU users can also report at https://discord.com/report" },
      { name: "Botlabs bots (YAGPDB, Carl-Bot, Fredboat, Ayana, Piggy)", contact_type: :other, method: :email, email: "jasper@phish.directory", priority: 50, notes: "Internal routing - Jasper will reach out via Discord to @blackwolfwoof or @jbziscool." },
      { name: "Wick Bot", contact_type: :other, method: :web_form, email: "abuse@wickbot.org", web_form_url: "https://docs.google.com/forms/d/e/1FAIpQLSf6FNwdpiXNanQhSoAXr1cAIWLnFlPqfPCofO8p2pwsUtu2tQ/viewform", priority: 50 },
      { name: "LifeLock", contact_type: :other, method: :email, email: "spam@lifelock.com", priority: 50 },
      { name: "PasteBin", contact_type: :other, method: :email, email: "security@pastebin.com", priority: 50, notes: "Include who you are, why the item is abusive, and direct link(s). Write in English." },
      { name: "Dropbox", contact_type: :other, method: :email, email: "abuse@dropbox.com", priority: 50 },
      { name: "SugarSync", contact_type: :other, method: :email, email: "support@sugarsync.zendesk.com", priority: 50 },
      { name: "OpenProvider", contact_type: :other, method: :web_form, web_form_url: "https://www.openprovider.com/company/contact-us/report-abuse", priority: 50 },
      { name: "Wix", contact_type: :other, method: :web_form, web_form_url: "http://www.wix.com/upgrade/abuse#!spam-report/c18hy", priority: 50 },
      { name: "Weebly", contact_type: :other, method: :web_form, web_form_url: "https://www.weebly.com/spam", priority: 50 },

      # Security Vendors (priority: 20) - These receive all high-confidence reports
      # API keys must be configured in credentials or via admin UI
      { name: "CleanDNS", contact_type: :security_vendor, method: :api, api_endpoint: "https://api.cleandns.dev/v2/abuse/report", priority: 15, trusted_reporter: true, notes: "phish.directory is a CleanDNS trusted reporter. Uses XARF format. Forwards to NetBeacon for domains outside CleanDNS management." },
      { name: "Google Safe Browsing", contact_type: :security_vendor, method: :api, api_endpoint: "https://safebrowsing.googleapis.com/v4/threatHits", priority: 20, trusted_reporter: true, notes: "Requires API key. Reports URLs to Google's threat database." },
      { name: "URLScan.io", contact_type: :security_vendor, method: :api, api_endpoint: "https://urlscan.io/api/v1/scan/", priority: 20, notes: "Requires API key. Scans and archives phishing pages." },
      { name: "FishFish (Yuri)", contact_type: :security_vendor, method: :api, api_endpoint: "https://yuri.bots.lostluma.dev/phish/report", priority: 15, trusted_reporter: true, notes: "Community-curated phishing list. High-trust source. Submits via Lilly's yuri bot." },
      { name: "Phish Report", contact_type: :security_vendor, method: :api, api_endpoint: "https://phish.report/api/v0/cases", priority: 15, trusted_reporter: true, notes: "Phish Report takedown service. Creates cases and automates abuse reports to registrars/hosting." },
      { name: "APWG eCrime", contact_type: :security_vendor, method: :email, email: "reportphishing@apwg.org", priority: 20, trusted_reporter: true, notes: "Anti-Phishing Working Group. Industry consortium for fighting phishing." },
      { name: "Microsoft Security", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site", priority: 20, notes: "Reports to Microsoft Defender SmartScreen." },

      # Additional Email-based Security Vendors (priority: 20)
      { name: "US-CERT", contact_type: :security_vendor, method: :email, email: "phishing-report@us-cert.gov", priority: 20, notes: "US Computer Emergency Readiness Team." },
      { name: "FTC Spam", contact_type: :security_vendor, method: :email, email: "spam@uce.gov", priority: 20, notes: "Federal Trade Commission spam reporting." },
      { name: "Microsoft 365", contact_type: :security_vendor, method: :email, email: "phish@office365.microsoft.com", priority: 20, notes: "Microsoft 365 phishing reports." },
      { name: "OpenPhish", contact_type: :security_vendor, method: :email, email: "report@openphish.com", priority: 20, notes: "Community phishing feed." },

      # Security Vendor Web Forms (priority: 25) - From issue #8 comments
      { name: "Avira", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.avira.com/en/analysis/submit-url", priority: 25 },
      { name: "Dr. Web", contact_type: :security_vendor, method: :web_form, web_form_url: "https://support.drweb-av.de/new/urlfilter/", priority: 25 },
      { name: "Kaspersky", contact_type: :security_vendor, method: :web_form, web_form_url: "https://opentip.kaspersky.com/", priority: 25 },
      { name: "Symantec / Norton", contact_type: :security_vendor, method: :web_form, web_form_url: "https://sitereview.symantec.com/", priority: 25 },
      { name: "McAfee", contact_type: :security_vendor, method: :web_form, web_form_url: "https://sitelookup.mcafee.com/", priority: 25, notes: "Select real-time, click Check, and click Submit at the bottom." },
      { name: "Bitdefender", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.bitdefender.com/consumer/support/answer/29358/", priority: 25 },
      { name: "TrendMicro", contact_type: :security_vendor, method: :web_form, web_form_url: "https://global.sitesafety.trendmicro.com/index.php", priority: 25 },
      { name: "ESET", contact_type: :security_vendor, method: :web_form, web_form_url: "https://phishing.eset.com/en-us/report", priority: 25 },
      { name: "Palo Alto", contact_type: :security_vendor, method: :web_form, web_form_url: "https://urlfiltering.paloaltonetworks.com/", priority: 25 },
      { name: "Netcraft", contact_type: :security_vendor, method: :web_form, web_form_url: "https://report.netcraft.com/report", priority: 25, notes: "Also supports API with registration." },
      { name: "BrightCloud (Webroot)", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.brightcloud.com/tools/url-ip-lookup.php", priority: 25, notes: "Provides data to PaloAlto firewalls and many others." },
      { name: "Fortiguard", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.fortiguard.com/webfilter", priority: 25 },
      { name: "GOV.UK NCSC", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.ncsc.gov.uk/section/about-this-website/report-scam-website", priority: 25, notes: "UK National Cyber Security Centre." },
      { name: "Scumware", contact_type: :security_vendor, method: :web_form, web_form_url: "https://scumware.org/add_url.php", priority: 25 },
      { name: "Talos Intelligence", contact_type: :security_vendor, method: :web_form, web_form_url: "https://talosintelligence.com/", priority: 25, notes: "Cisco Talos threat intelligence." },
      { name: "AlphaMountain", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.alphamountain.ai/contact/", priority: 25 },
      { name: "Spam404", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.spam404.com/report.html", priority: 25 },
      { name: "Forcepoint", contact_type: :security_vendor, method: :web_form, web_form_url: "https://csi.forcepoint.com/", priority: 25 },
      { name: "CRDF ThreatCenter", contact_type: :security_vendor, method: :web_form, web_form_url: "https://threatcenter.crdf.fr/submit_url.html", priority: 25 },
      { name: "MalwareURL", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.malwareurl.com/submit.php", priority: 25 },
      { name: "Sucuri", contact_type: :security_vendor, method: :web_form, web_form_url: "https://abuse.sucuri.net/", priority: 25 },
      { name: "Cybercrime Tracker", contact_type: :security_vendor, method: :web_form, web_form_url: "https://cybercrime-tracker.net/submit.php", priority: 25 },
      { name: "Spamhaus", contact_type: :security_vendor, method: :web_form, web_form_url: "https://submit.spamhaus.org/submit", priority: 25 },
      { name: "Cyren", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.cyren.com/security-center/url-category-check-gate", priority: 25 },
      { name: "Bfore.ai", contact_type: :security_vendor, method: :web_form, web_form_url: "https://bfore.ai/support/", priority: 25 },
      { name: "Avast", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.avast.com/report-false-negative#pc", priority: 25 },
      { name: "CIRCL", contact_type: :security_vendor, method: :web_form, web_form_url: "https://www.circl.lu/urlabuse/", priority: 25, notes: "Luxembourg CERT. Shares with European partners." },
      { name: "Blue Coat / Symantec WebPulse", contact_type: :security_vendor, method: :web_form, web_form_url: "http://sitereview.bluecoat.com/sitereview.jsp", priority: 25 },

      # Crypto-specific (priority: 30)
      { name: "ChainPatrol", contact_type: :security_vendor, method: :web_form, web_form_url: "https://app.chainpatrol.io/chainpatrol/report", priority: 30, notes: "For crypto/web3 phishing sites." },

      # Russian CERTs - Required for .ru domains due to legal constraints
      { name: "FACCT / CERT-GIB", contact_type: :security_vendor, method: :email, email: "response@cert-gib.com", priority: 25, notes: "Russian CERT for .ru domains. Alternative: response@facct.ru" },
      { name: "NCIRCC (Russian National CERT)", contact_type: :security_vendor, method: :email, email: "incident@cert.gov.ru", priority: 25, notes: "Russian National CERT. Required for instructing Russian registrars to suspend domains." }
    ].freeze

    def self.seed!
      puts "Seeding abuse contacts..."
      created = 0
      updated = 0

      CONTACTS.each do |attrs|
        contact = Report::AbuseContact.find_by(name: attrs[:name])
        if contact
          contact.update!(attrs)
          updated += 1
        else
          Report::AbuseContact.create!(attrs)
          created += 1
        end
      end

      puts "Abuse contacts: #{created} created, #{updated} updated (#{CONTACTS.size} total)"
    end
  end
end
