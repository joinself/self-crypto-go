package selfcrypto

import "errors"

var (
	ErrNotEnoughRandom          = errors.New("random data provided insufficient")
	ErrInsufficientOutputBuffer = errors.New("output buffer provided is too small")
	ErrBadMessageVersion        = errors.New("bad message version")
	ErrBadMessageFormat         = errors.New("bad message format")
	ErrBadMessageMAC            = errors.New("bad message MAC")
	ErrBadMessageKeyID          = errors.New("bad message key id")
	ErrInvalidBase64Encoding    = errors.New("invalid base64 encoding")
	ErrBadAccountKey            = errors.New("bad account key")
	ErrUnknownPickleVersion     = errors.New("provided pickle is not of a supported version")
	ErrCorruptedPickle          = errors.New("provided pickle is corrupted")
	ErrBadSessionKey            = errors.New("bad session key")
	ErrUnknownMessageIndex      = errors.New("unknown message index")
	ErrUnsupportedPickleFormat  = errors.New("account pickle is of an unsupported legacy format")
	ErrBadSignature             = errors.New("bad signature")
	ErrInsufficientInputBuffer  = errors.New("input buffer provided is too small")
	ErrUnknown                  = errors.New("unknown error")
)

// Error returns a go error from a given olm error string
func Error(errtext string) error {
	switch errtext {
	case "SUCCESS":
		return nil
	case "NOT_ENOUGH_RANDOM":
		return ErrNotEnoughRandom
	case "OUTPUT_BUFFER_TOO_SMALL":
		return ErrInsufficientOutputBuffer
	case "BAD_MESSAGE_VERSION":
		return ErrBadMessageVersion
	case "BAD_MESSAGE_FORMAT":
		return ErrBadMessageFormat
	case "BAD_MESSAGE_MAC":
		return ErrBadMessageMAC
	case "BAD_MESSAGE_KEY_ID":
		return ErrBadMessageKeyID
	case "INVALID_BASE64":
		return ErrInvalidBase64Encoding
	case "BAD_ACCOUNT_KEY":
		return ErrBadAccountKey
	case "UNKNOWN_PICKLE_VERSION":
		return ErrUnknownPickleVersion
	case "CORRUPTED_PICKLE":
		return ErrCorruptedPickle
	case "BAD_SESSION_KEY":
		return ErrBadSessionKey
	case "UNKNOWN_MESSAGE_INDEX":
		return ErrUnknownMessageIndex
	case "BAD_LEGACY_ACCOUNT_PICKLE":
		return ErrUnsupportedPickleFormat
	case "BAD_SIGNATURE":
		return ErrBadSignature
	case "OLM_INPUT_BUFFER_TOO_SMALL":
		return ErrInsufficientOutputBuffer
	default:
		return ErrUnknown
	}
}
