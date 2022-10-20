# Copyright 2009 by Tim Becker (tim.becker@kuriostaet.de)
# MIT License, for details, see the LICENSE file accompaning
# this distribution

require 'pry-nav'
require 'pry'

require 'lib/iso8583'


# Example of a protocol specification based on:
# http://www.berlin-group.org/documents/BG_Authorisation_3.0.pdf
# The Berlin Groups Authorisation Interface specification.
# No gurantees are made that this is an accurate implemenation.
# It currently serves as an example only.

module ISO8583

  class FirstDataMessage < Message
    mti_format N, :length => 4
    mti 0100, "Authorization Request"
    mti 0110, "Authorization Request Response"
    mti 1100, "Authorization Request Acquirer Gateway"
    mti 1110, "Authorization Request Response Issuer Gateway"
    mti 1420, "Reversal Advice Acquirer Gateway" 
    mti 1421, "Reversal Advice Repeat Acquirer Gateway" 
    mti 1430, "Reversal Advice Response Issuer Gateway" 
    mti 1804, "Network Management Request Acquirer Gateway or Issuer Gateway"
    mti 1814, "Network Management Request Response Issuer Gateway or Acquirer Gateway"

    bmp  2, "Primary Account Number (PAN)",               LVAR_BZ,    :max    => 19
    bmp  3,  "Processing Code",                           N,         :length =>  6
    bmp  4,  "Amount (Transaction)",                      N,         :length => 12
    bmp  6,  "Amount, Cardholder Billing" ,               N,         :length => 12
    bmp  7,  "Date and Time, Transmission"  ,             MMDDhhmmss
    bmp 10, "Conversion Rate, Cardholder Billing",        N,         :length =>  8
    bmp 11, "System Trace Audit Number (STAN)",           N,         :length =>  6
    bmp 12, "Date and Time, Local Transaction",           YYMMDDhhmmss
    bmp 14, "Date, Expiration",                           YYMM
    bmp 22, "POS Data Code",                              AN,        :length => 12
    bmp 23, "Card Sequence Number",                       N,         :length =>  3
    bmp 24, "Function Code",                              N,         :length =>  3
    bmp 25, "Message Reason Code",                        N,         :length =>  4
    bmp 26, "Card Acceptor Business Code",                N,         :length =>  4
    bmp 30, "Amounts, Original",                          N,         :length => 24
    bmp 32, "Acquiring Institution Identification Code",  LLVAR_N,   :max    => 11
    bmp 35, "Track 2 Data",                               LLVAR_Z,   :max    => 37
    bmp 37, "Retrieval Reference Number",                 ANP,       :length => 12
    bmp 38, "Approval Code",                              ANP,       :length =>  6
    bmp 39, "Action Code",                                N,         :length =>  3
    bmp 41, "Card Acceptor Terminal Identification",      ANS,       :length =>  8
    bmp 42, "Card Acceptor Identification Code",          ANS,       :length => 15
    bmp 43, "Card Acceptor Name/Location",                LLVAR_ANS, :max    => 56
    bmp 49, "Currency Code, Transaction",                 N,         :length =>  3
    bmp 51, "Currency Code, Cardholder Billing",          N,         :length =>  3
    bmp 52, "Personal Identification Number (PIN) Data",  B,         :length =>  8
    bmp 53, "Security Related Control Information",       LLVAR_B,   :max    => 48
    bmp 54, "Amounts, Additional",                        LLLVAR_ANS,:max    => 40

    bmp 55, "Integrated Circuit Card (ICC) System Related Data", LLLVAR_B,   :max    => 255
    bmp 56, "Original Data Elements",                            LLVAR_N,    :max    => 35
    bmp 58, "Authorizing Agent Institution Identification Code", LLVAR_N,    :max    => 11
    bmp 59, "Additional Data - Private",                         LLLVAR_ANS, :max    => 67
    bmp 64, "Message Authentication Code (MAC) Field",           B,          :length => 8
    
    bmp_alias  2, :pan
    bmp_alias  3, :proc_code
    bmp_alias  4, :amount
    bmp_alias 12, :exp_date
  end

end

if __FILE__==$0

#{“message_type”=>“\u0001\u0000", “card_type”=>“Visa”, “pan”=>“3566007770017510", “transaction_processing_code”=>“000000", “amount”=>“000000003650", “transmission_datetime”=>“0504191856", “system_trace”=>“000099", “transaction_time”=>“151856", “transaction_date”=>“0504", “card_expiration_date”=>“2512", “merchant_category_code”=>“5045", “pos_mode_and_pin_capability”=>“0901", “network_intl_id”=>“0001", “pos_condition_code”=>“00", “track2_data”=>“3566007770017510d251210123456789", “retrieval_reference_number”=>“0000CXQJ7DFS”, “terminal_id”=>“2a28fab7", “merchant_id”=>“000445190514999", “alternate_merchant_name_location”=>“DESCRIPTOR          12115 LACKLAND      CHICAGO       IL  63146  USA        “, “currency_code”=>“0840", “merchant_postal_code”=>“631460000", “additional_pos_information”=>“45", “table_data”=>“”, “aci”=>“X”, “transaction_identifier”=>”        “, “validation_code”=>”  “, “market_specific_indicator”=>” “, “rps”=>” “, “first_authorized_amount”=>“000000000000", “total_authorized_amount”=>“000000000000", “version”=>“01", “balance_info”=>“1", “partial_approval”=>“1", “number_of_entries”=>“1", “visa_id”=>“\v”, “agent_unique_id”=>”   “, “visa_auar”=>“\u0000\u0000\u0000\u0000\u0000\u0000", “tpp_id”=>“TBT114", “tc”=>“TC015400111100000000", “ar”=>“AR0040000"}


  intext = "\x01\x00r<E\x80(\xE0\x802\x165f\x00wp\x01u\x10\x00\x00\x00\x00\x00\x00\x006P\x05\x04\x19\x18V\x00\x00\x99\x15\x18V\x05\x04%\x12PE\t\x01\x00\x01\x0025f\x00wp\x01u\x10\xD2Q!\x01#Eg\x890000CXQJ7DFS2a28fab7000445190514999DESCRIPTOR                    12115 LACKLAND           CHICAGO             IL   63146    USA               \b@\t631460000E\x01\x19\x00H14X                     000000000000000000000000\x00\x0568211\x00#69011\v     \x00\x00\x00\x00\x00\x00TBT114\x00\x02DS\x001SDTC015400111100000000AR0040000”\
[0cfc37bf-5bbc-4c17-9fdb-35349a6e78d4] [FIRSTDATA AUTH CONNECTION] Response: “\x01\x102 \x01\x80\x0E\x80\x00\x02\x00\x00\x00\x00\x00\x00\x006P\x05\x04\x19\x18V\x00\x00\x99\x00\x01\x000000CXQJ7DFSOK8204002a28fab7\x01\x99\x00H14X165169193623112      000000000000000000000000\x00\x1822APPROVAL        \x00\x86DS01000000\x1C02110212\x1C030210\x1C04151856\x1C050504\x1C0600\x1C070200010010500\x1C0802\x1C10165169193623112\x009SDZX003EAVTC015400111100000000AR004O   "

binding.pry
  mes2 = ISO8583::FirstDataMessage.parse intext
  puts mes2.to_s

  mes = ISO8583::FirstDataMessage.new
  mes.mti = 0100
  mes[2] = 474747474747
  mes["Processing Code"] = "123456"

  #pan = mes["Primary Account Number (PAN)"]
  #mes.pan = 47474747474747

  #puts mes.pan
  puts mes.to_b
  puts mes.to_s
  
end
