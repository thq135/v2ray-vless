package encoding

import (
	cryptorand "crypto/rand"
	"io"

	"v2ray.com/core/common"
	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/crypto"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/proxy/vless"
)

// ServerSession keeps information for a session in VLess server.
type ServerSession struct {
	userValidator  *vless.UserValidator
	responseAuther byte
}

// NewServerSession creates a new ServerSession, using the given UserValidator.
// The ServerSession instance doesn't take ownership of the validator.
func NewServerSession(validator *vless.UserValidator) *ServerSession {
	return &ServerSession{
		userValidator: validator,
	}
}

// DecodeRequestHeader decodes and returns (if successful) a RequestHeader from an input stream.
func (s *ServerSession) DecodeRequestHeader(reader io.Reader) (*protocol.RequestHeader, error) {

	buffer := buf.New()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, protocol.IDBytesLen); err != nil {
		return nil, newError("failed to read request header").Base(err)
	}

	var id [16]byte
	copy(id[:], buffer.Bytes())
	user, valid := s.userValidator.Get(id)
	if !valid {
		return nil, newError("invalid user")
	}

	request := &protocol.RequestHeader{
		User: user,
	}

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 2); err != nil {
		return nil, newError("failed to read request header").Base(err)
	}

	s.responseAuther = buffer.Byte(0)
	request.Command = protocol.RequestCommand(buffer.Byte(1))

	switch request.Command {
	case protocol.RequestCommandMux:
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = 0
	case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
		if addr, port, err := addrParser.ReadAddressPort(buffer, reader); err == nil {
			request.Address = addr
			request.Port = port
		}
	}

	if request.Address == nil {
		return nil, newError("invalid remote address")
	}

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, newError("failed to read request mess").Base(err)
	}

	messNameLen := int32(buffer.Byte(0))
	if messNameLen != 0 {

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, messNameLen+1); err != nil {
			return nil, newError("failed to read request messName").Base(err)
		}

		request.MessName = string(buffer.BytesTo(messNameLen))
		//newError("MessName: " + request.MessName).AtError().WriteToLog()
		messSeedLen := int32(buffer.Byte(messNameLen))
		if messSeedLen != 0 {

			buffer.Clear()
			if _, err := buffer.ReadFullFrom(reader, messSeedLen); err != nil {
				return nil, newError("failed to read request messSeed").Base(err)
			}

			//request.MessSeed = buffer.Bytes()
			// MessSeed is a reference to buffer, which will be released when this function ends.

			request.MessSeed = make([]byte, messSeedLen)
			copy(request.MessSeed, buffer.Bytes())

			//newError("Mess1111: " + strconv.Itoa(len(request.MessSeed)) + strconv.Itoa(int(request.MessSeed[0])) + strconv.Itoa(int(request.MessSeed[15]))).AtError().WriteToLog()

		}

	}

	return request, nil
}

// DecodeRequestBody returns Reader from which caller can fetch decrypted body.
func (s *ServerSession) DecodeRequestBody(request *protocol.RequestHeader, reader io.Reader) buf.Reader {

	switch request.MessName {
	case "shake":

		//newError("Mess2222: " + strconv.Itoa(len(request.MessSeed)) + strconv.Itoa(int(request.MessSeed[0])) + strconv.Itoa(int(request.MessSeed[15]))).AtError().WriteToLog()

		var sizeParser crypto.ChunkSizeDecoder = crypto.PlainChunkSizeParser{}
		sizeParser = NewShakeSizeParser(request.MessSeed)
		var padding crypto.PaddingLengthGenerator
		//padding = sizeParser.(crypto.PaddingLengthGenerator)

		if request.Command.TransferType() == protocol.TransferTypeStream {
			return crypto.NewChunkStreamReader(sizeParser, reader)
		}
		auth := &crypto.AEADAuthenticator{
			AEAD:                    new(NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
		return crypto.NewAuthenticationReader(auth, sizeParser, reader, protocol.TransferTypePacket, padding)

	default:

		return buf.NewReader(reader)

	}

}

// EncodeResponseHeader writes encoded response header into the given writer.
func (s *ServerSession) EncodeResponseHeader(response *protocol.RequestHeader, writer io.Writer) {

	buffer := buf.StackNew()
	defer buffer.Release()

	common.Must(buffer.WriteByte(s.responseAuther))
	common.Must(buffer.WriteByte(byte(len(response.MessName))))

	if response.MessName != "" {
		common.Must2(buffer.Write([]byte(response.MessName)))

		switch response.MessName {
		case "shake":

			response.MessSeed = make([]byte, 16)
			cryptorand.Read(response.MessSeed)
			common.Must(buffer.WriteByte(byte(len(response.MessSeed))))
			common.Must2(buffer.Write(response.MessSeed))

		default:

			common.Must(buffer.WriteByte(0))

		}

	}

	common.Must2(writer.Write(buffer.Bytes()))
}

// EncodeResponseBody returns a Writer that auto-encrypt content written by caller.
func (s *ServerSession) EncodeResponseBody(response *protocol.RequestHeader, writer io.Writer) buf.Writer {

	switch response.MessName {
	case "shake":

		var sizeParser crypto.ChunkSizeEncoder = crypto.PlainChunkSizeParser{}
		sizeParser = NewShakeSizeParser(response.MessSeed)
		var padding crypto.PaddingLengthGenerator
		//padding = sizeParser.(crypto.PaddingLengthGenerator)

		if response.Command.TransferType() == protocol.TransferTypeStream {
			return crypto.NewChunkStreamWriter(sizeParser, writer)
		}
		auth := &crypto.AEADAuthenticator{
			AEAD:                    new(NoOpAuthenticator),
			NonceGenerator:          crypto.GenerateEmptyBytes(),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
		return crypto.NewAuthenticationWriter(auth, sizeParser, writer, protocol.TransferTypePacket, padding)

	default:

		return buf.NewWriter(writer)

	}

}
