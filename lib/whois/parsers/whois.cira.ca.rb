require_relative 'base'

module Whois
  class Parsers
    class WhoisCiraCa < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
         !!(content_for_scanner =~ /Not found:/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Creation Date.?:\s+([0-9 -:]+)/
          Time.parse($1).utc
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Registry Expiry Date.?:\s+([0-9 -:]+)/
          Time.parse($1 + " UTC").utc
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/Name Server: (([a-zA-Z0-9\-]+|[a-zA-Z0-9\-]*\*[a-zA-Z0-9\-]*)(\.[a-zA-Z0-9\-]+){2,3})/).map do |name|
          Parser::Nameserver.new(:name => name[0])
        end
      end
    end
  end
end
