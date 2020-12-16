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
    class WhoisDenicDe < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
         !!(content_for_scanner =~ /Status: free/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on 

      property_not_supported :expires_on

      property_supported :nameservers do
        content_for_scanner.scan(/Nserver: (([a-zA-Z0-9\-]+|[a-zA-Z0-9\-]*\*[a-zA-Z0-9\-]*)(\.[a-zA-Z0-9\-]+){2,3})/).map do |name|
          Parser::Nameserver.new(:name => name[0])
        end
      end
    end

  end
end
