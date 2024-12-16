package dns

import "errors"

type QR uint8

const (
	Query QR = iota
	Response
)

var (
	ErrorInvalidHeader      = errors.New("header: invalid")
	ErrorInvalidQNameLength = errors.New("qname: buffer is empty")
)

func (qr QR) String() string {
	switch qr {
	case Query:
		return "QUERY"
	case Response:
		return "RESPONSE"
	default:
		panic("Invalid Query/Response")
	}
}

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
		return "STD"
	case Inverse:
		return "INVERSE"
	case ServerStatus:
		return "SERVER STATUS"
	case AFA:
		return "AFA"
	case Notify:
		return "Notify"
	case Update:
		return "Update"
	default:
		return "RESERVED"
	}
}

type Authoritative uint8

const (
	AuthoritativeYes Authoritative = iota
	AuthoritativeNo
)

func (a Authoritative) String() string {
	switch a {
	case AuthoritativeYes:
		return "AUTHYES"
	case AuthoritativeNo:
		return "AUTHNO"
	default:
		panic("unknown authoritative response")
	}
}

type Truncation uint8

const (
	TruncationYes Truncation = iota
	TruncationNo
)

func (a Truncation) String() string {
	switch a {
	case TruncationYes:
		return "TRUNCYES"
	case TruncationNo:
		return "TRUNCNO"
	default:
		panic("unknown truncation")
	}
}

type RecursionDesired uint8

const (
	RecursionDesiredYes RecursionDesired = iota
	RecursionDesiredNo
)

func (a RecursionDesired) String() string {
	switch a {
	case RecursionDesiredYes:
		return "RECURSION DESIRED YES"
	case RecursionDesiredNo:
		return "RECURSION DESIRED NO"
	default:
		panic("unknown RD")
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

type RecursionAvailable uint8

const (
	RecursionAvailableYes RecursionAvailable = iota
	RecursionAvailableNo
)

func (a RecursionAvailable) String() string {
	switch a {
	case RecursionAvailableYes:
		return "RECURSION AVAIALABLE YES"
	case RecursionAvailableNo:
		return "RECURSION AVAIALABLE NO"
	default:
		panic("unknown RD")
	}
}

type qtype uint8

const (
	A     qtype = iota + 1 // a host address
	Ns                     // an authoritative name server
	Md                     // a mail destination (Obsolete - use MX)
	Mf                     // a mail forwarder (Obsolete - use MX)
	Cname                  // the canonical name for an alias
	Soa                    // marks the start of a zone of authority
	Mb                     // a mailbox domain name (EXPERIMENTAL)
	Mg                     // a mail group member (EXPERIMENTAL)
	Mr                     // a mail rename domain name (EXPERIMENTAL)
	Null                   // a null RR (EXPERIMENTAL)
	Wks                    // a well known service description
	Ptr                    // a domain name pointer
	Hinfo                  // host information
	Minfo                  // mailbox or mail list information
	Mx                     // mail exchange
	Txt                    // text strings
)

// QTYPE fields appear in the question part of a query.  QTYPES are a
// superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
// following QTYPEs are defined:
const (
	Axfr  qtype = iota + 251 // A request for a transfer of an entire zone
	Mailb                    // A request for mailbox-related records (MB, MG or MR)
	Maila                    // A request for mail agent RRs (Obsolete - see MX)
	Star                     // A request for all records
)

func (qt qtype) String() string {
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
	default:
		panic("unknown qtype")
	}
}

type class int

const (
	In class = iota + 1 // the Internet
	Cs                  // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	Ch                  // the CHAOS class
	Hs                  // Hesiod [Dyer 87]
	classStar
)

func (c class) String() string {
	switch c {
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
		panic("invalid class")
	}
}

// bit masks for common fields
const (
	QrMask     uint16 = 0x8000 // 1 bit
	OPCodeMask        = 0x7800 // 4 bits
	AAMask            = 0x0400 // 1 bit
	TCMask            = 0x0200 // 1 bit
	RDMask            = 0x0100 // 1 bit
	RAMask            = 0x0080 // 1 bit
	ZMask             = 0x0040 // 1 bit
	RCodeMask         = 0x003F // 4 bits
)
