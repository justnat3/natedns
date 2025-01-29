package dns

import (
	"errors"
)

var (
	ErrorInvalidHeader      = errors.New("header: invalid")
	ErrorInvalidQNameLength = errors.New("qname: buffer is empty")
)

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
type Opcode uint8

const (
	Std Opcode = iota
	Inverse
	ServerStatus
	AFA
	Notify
	Update
	Reserved // 3 - 15
)

func (o Opcode) String() string {
	switch o {
	case Std:
		return "Standard"
	case Inverse:
		return "Inverse"
	case ServerStatus:
		return "Server STatus"
	case AFA:
		return "AFA"
	case Notify:
		return "Notify"
	case Update:
		return "Update"
	default:
		return "Reserved"
	}
}

type ResponseCode uint8

const (
	NoError ResponseCode = iota
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
	YXDomain
	YXRRSet
	NXRRSet
	NotAuth
	NotZone
	N1
	N2
	N3
	N4
	N5
	BADVERS
	BADSIG
	BADKEY
	BADTIME
	BADMODE
	BADNAME
	BADALG
	BADTRUNC
)

func (rc ResponseCode) String() string {
	switch rc {
	case NoError:
		return "No Error"
	case FormErr:
		return "FormErr"
	case ServFail:
		return "ServFail"
	case NXDomain:
		return "NXDomain"
	case NotImp:
		return "NotImp"
	case Refused:
		return "Refused"
	case YXDomain:
		return "YXDomain"
	case YXRRSet:
		return "YXRRSet"
	case NXRRSet:
		return "NXRRSet"
	case NotAuth:
		return "NoAuth"
	case NotZone:
		return "NotZone"
	case N1:
		return "."
	case N2:
		return "."
	case N3:
		return "."
	case N4:
		return "."
	case N5:
		return "."
	case BADVERS:
		return "BADVERS"
	case BADSIG:
		return "BADSIG"
	case BADKEY:
		return "BADKEY"
	case BADTIME:
		return "BADTIME"
	case BADMODE:
		return "BADMODE"
	case BADNAME:
		return "BADNAME"
	case BADALG:
		return "BADALG"
	case BADTRUNC:
		return "BADTRUNC"
	default:
		panic("invalid response code")
	}
}

type QueryType uint8

const (
	Unknown QueryType = iota // ??
	A                        // a host address
	Ns                       // an authoritative name server
	Md                       // a mail destination (Obsolete - use MX)
	Mf                       // a mail forwarder (Obsolete - use MX)
	Cname                    // the canonical name for an alias
	Soa                      // marks the start of a zone of authority
	Mb                       // a mailbox domain name (EXPERIMENTAL)
	Mg                       // a mail group member (EXPERIMENTAL)
	Mr                       // a mail rename domain name (EXPERIMENTAL)
	Null                     // a null RR (EXPERIMENTAL)
	Wks                      // a well known service description
	Ptr                      // a domain name pointer
	Hinfo                    // host information
	Minfo                    // mailbox or mail list information
	Mx                       // mail exchange
	Txt                      // text strings
	Opt     QueryType = 41   // optional?
)

// QTYPE fields appear in the question part of a query.  QTYPES are a
// superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
// following QTYPEs are defined:
const (
	Axfr  QueryType = iota + 251 // A request for a transfer of an entire zone
	Mailb                        // A request for mailbox-related records (MB, MG or MR)
	Maila                        // A request for mail agent RRs (Obsolete - see MX)
	Star                         // A request for all records
)

func TypeFromString(qt string) QueryType {
	switch qt {
	case "A":
		return A
	case "NS":
		return Ns
	case "MD":
		return Md
	case "MF":
		return Mf
	case "CNAME":
		return Cname
	case "SOA":
		return Soa
	case "MB":
		return Mb
	case "MG":
		return Mg
	case "MR":
		return Mr
	case "NULL":
		return Null
	case "WKS":
		return Wks
	case "PTR":
		return Ptr
	case "HINFO":
		return Hinfo
	case "MINFO":
		return Minfo
	case "MX":
		return Mx
	case "TXT":
		return Txt
	case "OPT":
		return Opt
	default:
		return Unknown
	}
}

func (qt QueryType) String() string {
	switch qt {
	case A:
		return "A"
	case Ns:
		return "NS"
	case Md:
		return "MD"
	case Mf:
		return "MF"
	case Cname:
		return "CNAME"
	case Soa:
		return "SOA"
	case Mb:
		return "MB"
	case Mg:
		return "MG"
	case Mr:
		return "MR"
	case Null:
		return "NULL"
	case Wks:
		return "WKS"
	case Ptr:
		return "PTR"
	case Hinfo:
		return "HINFO"
	case Minfo:
		return "MINFO"
	case Mx:
		return "MX"
	case Txt:
		return "TXT"
	case Opt:
		return "OPT"
	default:
		return "UNKNOWN"
	}
}

type QueryClass int

const (
	UnknownClass QueryClass = iota
	In                      // the Internet
	Cs                      // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	Ch                      // the CHAOS class
	Hs                      // Hesiod [Dyer 87]
	classStar
)

func (c QueryClass) String() string {
	switch c {
	case UnknownClass:
		return ""
	case In:
		return "IN"
	case Cs:
		return "CS"
	case Ch:
		return "CH"
	case Hs:
		return "HS"
	case classStar:
		return "Class Star"
	default:
		println("INCORRECT_CLASS:", c)
		return ""
	}
}

func ClassFromString(c string) QueryClass {
	switch c {
	case "":
		return UnknownClass
	case "IN":
		return In
	case "CS":
		return Cs
	case "CH":
		return Ch
	case "HS":
		return Hs
	case "*":
		return classStar
	default:
		return UnknownClass
	}

}
