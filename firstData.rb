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
    mti_format PT, :length => 2
    mti "\x01\x00", "Authorization Request"
    mti "\x01\x10", "Authorization Request Response"
    mti "\x02\x00", "Authorization/Financial Transaction Request"
    mti "\x02\x10", "Authorization/Financial Transaction Request Response"
    mti "\x02\x20", "E-Commerce Debit Completion Request (Non Host Capture)"
    mti "\x02\x30", "E-Commerce Debit Completion Response (Non Host Capture)"
    mti "\x04\x00", "Reversal Request"
    mti "\x04\x10", "Reversal Request Response"
    mti "\x08\x00", "Network Management Request"
    mti "\x08\x10", "Network Management Request Response"


    bmp  2, "Primary Account Number (PAN)",               LLVAR_BCDZNibble,:max    => 19
    bmp  3,  "Processing Code",                           N_BCD,     :length =>  3
    bmp  4,  "Amount (Transaction)",                      N_BCD,     :length =>  6
    bmp  7,  "Date and Time, Transmission"  ,             MMDDhhmmss
    bmp 11, "System Trace Audit Number (STAN)",           N_BCD,     :length =>  3
    bmp 12, "Time, Local Transmission",                   Hhmmss
    bmp 13, "Date, Local Transmission",                   MMDD
    bmp 14, "Date, Expiration",                           N_BCD,     :length =>  2
    bmp 18, "Merchant Catagory",                          N_BCD,     :length =>  2
    bmp 22, "POS Entry Mode & Capabilities",              N_BCD,     :length =>  2
    bmp 23, "Card Sequence Number",                       N_BCD,     :length =>  2
    bmp 24, "Network Internation ID",                     N_BCD,     :length =>  2
    bmp 25, "POS Condition Code",                         N_BCD,     :length =>  1
    bmp 28, "Merchant Surcharge",                         ANS,       :length =>  9
    bmp 31, "Acquirer Reference Data",                    LLVAR_BCANZ, :max    => 99 #payload is ASCII, not packed numbers
    bmp 32, "Acquiring Institution Identification Code",  LLVAR_BCDZNibble, :max    => 6
    bmp 35, "Track 2 Data",                               LLVAR_BCANZNibble, :max    => 37
    bmp 37, "Retrieval Reference Number",                 ANP,       :length => 12
    bmp 38, "Approval Code",                              ANP,       :length =>  6
    bmp 39, "Action Code",                                N,         :length =>  3
    bmp 41, "Card Acceptor Terminal Identification",      ANS,       :length =>  8
    bmp 42, "Card Acceptor Identification Code",          ANS,       :length => 15
    bmp 43, "Card Acceptor Name/Location",                ANS,       :length => 107
#    bmp 44, "Additional Response Data",                  LLLLVAR_BCANZ
    bmp 45, "Track 1 Data",                               LLVAR_BCANZ,:max    => 76
#    bmp 48, "First Data Private Use Data Element",                               

    bmp 49, "Transaction Currency Code",                  N_BCD,     :length =>  2
    bmp 52, "Encrypted PIN Data",                         B,         :length =>  8
    bmp 54, "Amounts, Additional",                        LLLLVAR_ANS, :max    => 12
    bmp 55, "EMV Data",                                   LLLLVAR_ANS, :max    => 999    
    bmp 59, "Merchant Zip/Postal Code",                   LVAR_ANS,  :max    => 9
    bmp 60, "Additional POS Information",                 N_BCD,     :length => 1

    bmp 63, "First Data Private Use Data Element",        LLLVAR_ANS, :max    => 999
    
    bmp_alias  2, :pan
    bmp_alias  3, :proc_code
    bmp_alias  4, :amount
    bmp_alias 12, :exp_date
  end

end

if __FILE__==$0

#{“message_type”=>“\u0001\u0000", “card_type”=>“Visa”, “pan”=>“3566007770017510", “transaction_processing_code”=>“000000", 
# “amount”=>“000000003650", “transmission_datetime”=>“0504191856", “system_trace”=>“000099", 
# “transaction_time”=>“151856", “transaction_date”=>“0504", “card_expiration_date”=>“2512", 
# “merchant_category_code”=>“5045", “pos_mode_and_pin_capability”=>“0901", “network_intl_id”=>“0001", 
# “pos_condition_code”=>“00", “track2_data”=>“3566007770017510d251210123456789",
# “retrieval_reference_number”=>“0000CXQJ7DFS”, “terminal_id”=>“2a28fab7", “merchant_id”=>“000445190514999", 
# “alternate_merchant_name_location”=>“DESCRIPTOR          12115 LACKLAND      CHICAGO       IL  63146  USA        “, 
# “currency_code”=>“0840", “merchant_postal_code”=>“631460000", “additional_pos_information”=>“45", “table_data”=>“”, 
# “aci”=>“X”, “transaction_identifier”=>”        “, “validation_code”=>”  “, “market_specific_indicator”=>” “, 
# “rps”=>” “, “first_authorized_amount”=>“000000000000", “total_authorized_amount”=>“000000000000", “version”=>“01", 
# “balance_info”=>“1", “partial_approval”=>“1", “number_of_entries”=>“1", “visa_id”=>“\v”, “agent_unique_id”=>”   “, 
# “visa_auar”=>“\u0000\u0000\u0000\u0000\u0000\u0000", “tpp_id”=>“TBT114", “tc”=>“TC015400111100000000", “ar”=>“AR0040000"}



###  field 63
# "\x01\x19\x00H14X                     000000000000000000000000\x00\x0568211\x00#69011\v     \x00\x00\x00\x00\x00\x00TBT114\x00\x02DS\x001SDTC015400111100000000AR0040000\xE2\x80\x9D[0cfc37bf-5bbc-4c17-9fdb-35349a6e78d4] [FIRSTDATA AUTH CONNECTION] Response: \xE2\x80\x9C\x01\x102 \x01\x80\x0E\x80\x00\x02\x00\x00\x00\x00\x00\x00\x006P\x05\x04\x19\x18V\x00\x00\x99\x00\x01\x000000CXQJ7DFSOK8204002a28fab7\x01\x99\x00H14X165169193623112      000000000000000000000000\x00\x1822APPROVAL        \x00\x86DS01000000\x1C02110212\x1C030210\x1C04151856\x1C050504\x1C0600\x1C070200010010500\x1C0802\x1C10165169193623112\x009SDZX003EAVTC015400111100000000AR004O   "



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
