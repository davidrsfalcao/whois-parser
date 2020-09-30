#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.nic.co server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicCo < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /No Data Found\n/)
      end

      property_supported :registered? do
        !available?
      end

      property_supported :created_on do
        if content_for_scanner =~ /Creation Date.?:\s+([^\r\n]+)/
          Time.parse($1)
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Updated Date.?:\s+([^\r\n]+)/
          Time.parse($1)
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Registry Expiry Date.?:\s+([^\r\n]+)/
          Time.parse($1)
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/Name Server: (([a-zA-Z0-9]+|[a-zA-Z0-9]*\*[a-zA-Z0-9]*)(\.[a-zA-Z0-9]+){2,3})/).map do |name|
          Parser::Nameserver.new(:name => name[0])
        end
      end
    end
  end
end
