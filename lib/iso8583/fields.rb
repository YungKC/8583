#--
# Copyright 2009 by Tim Becker (tim.becker@kuriostaet.de)
# MIT License, for details, see the LICENSE file accompaning
# this distribution
#++

module ISO8583

  # This file contains a number of preinstantiated Field definitions. You
  # will probably need to create own fields in your implementation, please
  # see Field and Codec for further discussion on how to do this.
  # The fields currently available are those necessary to implement the 
  # Berlin Groups Authorization Spec.
  #
  # The following fields are available:
  #
  # [+LL+]           special form to de/encode variable length indicators, two bytes ASCII numerals
  # [+LLL+]          special form to de/encode variable length indicators, two bytes ASCII numerals
  # [+LL_BCD+]       special form to de/encode variable length indicators, two BCD digits
  # [+LLVAR_N+]      two byte variable length ASCII numeral, payload ASCII numerals
  # [+LLLVAR_N+]     three byte variable length ASCII numeral, payload ASCII numerals
  # [+LLVAR_Z+]      two byte variable length ASCII numeral, payload Track2 data 
  # [+LLVAR_AN+]    two byte variable length ASCII numeral, payload ASCII
  # [+LLVAR_ANS+]    two byte variable length ASCII numeral, payload ASCII+special
  # [+LLLVAR_AN+]   three byte variable length ASCII numeral, payload ASCII
  # [+LLLVAR_ANS+]   three byte variable length ASCII numeral, payload ASCII+special
  # [+LLVAR_B+]      Two byte variable length binary payload
  # [+LLLVAR_B+]     Three byte variable length binary payload
  # [+A+]            fixed length letters, represented in ASCII
  # [+N+]            fixed lengh numerals, repesented in ASCII, padding right justified using zeros
  # [+AN+]          fixed lengh ASCII [A-Za-z0-9], padding left justified using spaces.
  # [+ANP+]          fixed lengh ASCII [A-Za-z0-9] and space, padding left, spaces
  # [+ANS+]          fixed length ASCII  [\x20-\x7E], padding left, spaces
  # [+B+]            binary data, padding left using nulls (0x00)
  # [+MMDDhhmmss+]   Date, formatted as described in ASCII numerals
  # [+MMDD+]         Date, formatted as described in ASCII numerals
  # [+YYMMDDhhmmss+] Date, formatted as named in ASCII numerals
  # [+YYMM+]         Expiration Date, formatted as named in ASCII numerals
  # [+Hhmmss+]       Date, formatted in ASCII hhmmss

  # Special form to de/encode variable length indicators, one bytes ASCII numerals 
  L          = Field.new
  L.name     = "L"
  L.length   = 1
  L.codec    = Null_Codec

  # Special form to de/encode variable length indicators, two bytes ASCII numerals 
  LL         = Field.new
  LL.name    = "LL"
  LL.length  = 2
  LL.codec   = ASCII_Number
  LL.padding = lambda {|value|
    sprintf("%02d", value)
  }
  # Special form to de/encode variable length indicators, three bytes ASCII numerals
  LLL         = Field.new
  LLL.name    = "LLL"
  LLL.length  = 3
  LLL.codec   = ASCII_Number
  LLL.padding = lambda {|value|
    sprintf("%03d", value)
  }

  L_BCD        = BCDField.new
  L_BCD.name   = "L_BCD"
  L_BCD.length = 1
  L_BCD.codec  = Packed_Number_RIGHT

  L_BCDHalf        = BCDHalfField.new
  L_BCDHalf.name   = "L_BCDHalf"
  L_BCDHalf.length = 1
  L_BCDHalf.codec  = Packed_Number_RIGHT

  L_BCDTwoHalf        = BCDHalfField.new
  L_BCDTwoHalf.name   = "L_BCDTwoHalf"
  L_BCDTwoHalf.length = 2
  L_BCDTwoHalf.codec  = Packed_Number_RIGHT

  LL_BCD        = Field.new
  LL_BCD.name   = "LL_BCD"
  LL_BCD.length = 2
  LL_BCD.codec  = Packed_Number_RIGHT

  LLL_BCD        = Field.new
  LLL_BCD.name   = "LLL_BCD"
  LLL_BCD.length = 3
  LLL_BCD.codec  = Packed_Number_RIGHT

  # length halved variable length Packed numeral, payload Packed NUMBER, zeropadded right (left justified)
  LLVAR_BCDZNibble        = Field.new
  LLVAR_BCDZNibble.name   = "LLVAR_BCDZNibble"
  LLVAR_BCDZNibble.length = L_BCDHalf
  LLVAR_BCDZNibble.codec  = Packed_Number_LEFT

  # length halved variable length Packed numeral, payload Packed NUMBER, zeropadded right (left justified)
  LLVAR_BCANZNibble        = Field.new
  LLVAR_BCANZNibble.name   = "LLVAR_BCANZNibble"
  LLVAR_BCANZNibble.length = L_BCDHalf
  LLVAR_BCANZNibble.codec  = Packed_LEFT

  # length halved variable length Packed numeral, payload Packed NUMBER, zeropadded right (left justified)
  LLVAR_BCANZ        = Field.new
  LLVAR_BCANZ.name   = "LLVAR_BCANZ"
  LLVAR_BCANZ.length = L_BCD
  LLVAR_BCANZ.codec  = Packed_LEFT

  # One byte variable length ASCII numeral, payload NUMBER, zeropadded right
  LVAR_BZ        = Field.new
  LVAR_BZ.name   = "LVAR_BZ"
  LVAR_BZ.length = L
  LVAR_BZ.codec  = Null_Codec

  # Two byte variable length ASCII numeral, payload ASCII numerals
  LLVAR_N        = Field.new
  LLVAR_N.name   = "LLVAR_N"
  LLVAR_N.length = LL
  LLVAR_N.codec  = ASCII_Number

  # Three byte variable length ASCII numeral, payload ASCII numerals
  LLLVAR_N        = Field.new
  LLLVAR_N.name   = "LLLVAR_N"
  LLLVAR_N.length = LLL
  LLLVAR_N.codec  = ASCII_Number

  # Two byte variable length ASCII numeral, payload Track2 data
  LLVAR_Z         = Field.new
  LLVAR_Z.name    = "LLVAR_Z"
  LLVAR_Z.length  = LL
  LLVAR_Z.codec   = Track2

  # Two byte variable length ASCII numeral, payload ASCII, fixed length, zeropadded (right)
  LLVAR_AN        = Field.new
  LLVAR_AN.name   = "LLVAR_AN"
  LLVAR_AN.length = LL
  LLVAR_AN.codec  = AN_Codec

  # One byte variable length ASCII numeral, payload ASCII+special
  LVAR_ANS        = Field.new
  LVAR_ANS.name   = "LVAR_ANS"
  LVAR_ANS.length = L_BCD
  LVAR_ANS.codec  = ANS_Codec

  # Two nibble variable length ASCII numeral, payload ASCII+special
  LLVAR_ANS        = Field.new
  LLVAR_ANS.name   = "LLVAR_ANS"
  LLVAR_ANS.length = L_BCD
  LLVAR_ANS.codec  = ANS_Codec

  # Three nibble variable length ASCII numeral, payload ASCII, fixed length, zeropadded (right)
  LLLVAR_AN        = Field.new
  LLLVAR_AN.name   = "LLLVAR_AN"
  LLLVAR_AN.length = LL_BCD
  LLLVAR_AN.codec  = AN_Codec

  # Three nibble variable length ASCII numeral, payload ASCII+special
  LLLVAR_ANS        = Field.new
  LLLVAR_ANS.name   = "LLLVAR_ANS"
  LLLVAR_ANS.length = LL_BCD
  LLLVAR_ANS.codec  = ANS_Codec

  # Four nibble variable length ASCII numeral, payload ASCII+special
  LLLLVAR_ANS        = Field.new
  LLLLVAR_ANS.name   = "LLLLVAR_ANS"
  LLLLVAR_ANS.length = LL_BCD
  LLLLVAR_ANS.codec  = ANS_Codec

  # Two byte variable length binary payload
  LLVAR_B        = Field.new
  LLVAR_B.name   = "LLVAR_B"
  LLVAR_B.length = LL
  LLVAR_B.codec  = Null_Codec


  # Three byte variable length binary payload
  LLLVAR_B        = Field.new
  LLLVAR_B.name   = "LLLVAR_B"
  LLLVAR_B.length = LLL
  LLLVAR_B.codec  = Null_Codec

  # Fixed lengh numerals, repesented in ASCII, padding right justified using zeros
  N = Field.new
  N.name  = "N"
  N.codec = ASCII_Number
  N.padding = lambda {|val, len|
    sprintf("%0#{len}d", val)
  }

  N_BCD = Field.new
  N_BCD.name  = "N_BCD"
  N_BCD.codec = Packed_Number_RIGHT

  PADDING_LEFT_JUSTIFIED_SPACES = lambda {|val, len|
    sprintf "%-#{len}s", val
  }

  # Fixed length ASCII letters [A-Za-z]
  A = Field.new
  A.name  = "A"
  A.codec = A_Codec

  # Pass through
  PT = Field.new
  PT.name = "PT"
  PT.codec = PASS_THROUGH_NO_STRIP

  # Fixed lengh ASCII [A-Za-z0-9], padding left justified using spaces.
  AN = Field.new
  AN.name  = "AN"
  AN.codec = AN_Codec
  AN.padding = PADDING_LEFT_JUSTIFIED_SPACES

  # Fixed lengh ASCII [A-Za-z0-9] and space, padding left, spaces
  ANP = Field.new
  ANP.name  = "ANP"
  ANP.codec = ANP_Codec
  ANP.padding = PADDING_LEFT_JUSTIFIED_SPACES

  # Fixed length ASCII  [\x20-\x7E], padding left, spaces
  ANS = Field.new
  ANS.name = ANS
  ANS.codec = ANS_Codec
  ANS.padding = PADDING_LEFT_JUSTIFIED_SPACES

  # Binary data, padding left using nulls (0x00)
  B = Field.new
  B.name  = "B"
  B.codec = Null_Codec
  B.padding = lambda {|val, len|
    while val.length < len
      val = val + "\000"
    end
    val
  }

  # Date, formatted as described in ASCII numerals
  MMDDhhmmss        = Field.new
  MMDDhhmmss.name   = "MMDDhhmmss"
  MMDDhhmmss.codec  = MMDDhhmmssCodec
  MMDDhhmmss.length = 5

  #Date, formatted as described in ASCII numerals
  YYMMDDhhmmss        = Field.new
  YYMMDDhhmmss.name   = "YYMMDDhhmmss"
  YYMMDDhhmmss.codec  = YYMMDDhhmmssCodec
  YYMMDDhhmmss.length = 6

  #Date, formatted as described in ASCII numerals
  YYMM        = Field.new
  YYMM.name   = "YYMM"
  YYMM.codec  = YYMMCodec
  YYMM.length = 2
  
  MMDD        = Field.new
  MMDD.name   = "MMDD"
  MMDD.codec  = MMDDCodec
  MMDD.length = 2

  Hhmmss        = Field.new
  Hhmmss.name   = "Hhmmss"
  Hhmmss.codec  = HhmmssCodec
  Hhmmss.length = 3

end
