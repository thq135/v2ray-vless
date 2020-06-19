package encoding

import (
	cryptorand "crypto/rand"
	"io"
	"math/rand"

	"v2ray.com/core/common"
	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/crypto"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/proxy/vless"
)

// ClientSession stores connection session info for VLess client.
type ClientSession struct {
	responseAuther byte
}

// NewClientSession creates a new ClientSession.
func NewClientSession() *ClientSession {
	//rand.Seed(time.Now().UnixNano())
	return &ClientSession{
		responseAuther: byte(rand.Intn(256)),
	}
}

func (c *ClientSession) EncodeRequestHeader(request *protocol.RequestHeader, writer io.Writer) error {

	buffer := buf.New()
	defer buffer.Release()

	account := request.User.Account.(*vless.MemoryAccount)
	common.Must2(buffer.Write(account.ID.Bytes()))
	common.Must2(buffer.Write([]byte{c.responseAuther, byte(request.Command)}))

	if request.Command != protocol.RequestCommandMux {
		if err := addrParser.WriteAddressPort(buffer, request.Address, request.Port); err != nil {
			return newError("failed to writer address and port").Base(err)
		}
	}

	common.Must(buffer.WriteByte(byte(len(request.MessName))))

	if request.MessName != "" {
		common.Must2(buffer.Write([]byte(request.MessName)))

		switch request.MessName {
		case "shake":

			request.MessSeed = make([]byte, 16)
			cryptorand.Read(request.MessSeed)
			common.Must(buffer.WriteByte(byte(len(request.MessSeed))))
			common.Must2(buffer.Write(request.MessSeed))

		default:

			common.Must(buffer.WriteByte(0))

		}

	}

	common.Must2(writer.Write(buffer.Bytes()))
	return nil
}

func (c *ClientSession) EncodeRequestBody(request *protocol.RequestHeader, writer io.Writer) buf.Writer {

	switch request.MessName {
	case "shake":

		var sizeParser crypto.ChunkSizeEncoder = crypto.PlainChunkSizeParser{}
		sizeParser = NewShakeSizeParser(request.MessSeed)
		var padding crypto.PaddingLengthGenerator
		//padding = sizeParser.(crypto.PaddingLengthGenerator)

		if request.Command.TransferType() == protocol.TransferTypeStream {
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

func (c *ClientSession) DecodeResponseHeader(reader io.Reader) (*protocol.RequestHeader, error) {

	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, newError("failed to read response header").Base(err).AtWarning()
	}

	if buffer.Byte(0) != c.responseAuther {
		return nil, newError("unexpected response header. Expecting ", int(c.responseAuther), " but actually ", int(buffer.Byte(0)))
	}

	response := &protocol.RequestHeader{}

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, newError("failed to read response mess").Base(err)
	}

	messNameLen := int32(buffer.Byte(0))
	if messNameLen != 0 {

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, messNameLen+1); err != nil {
			return nil, newError("failed to read response messName").Base(err)
		}

		response.MessName = string(buffer.BytesTo(messNameLen))
		messSeedLen := int32(buffer.Byte(messNameLen))
		if messSeedLen != 0 {

			buffer.Clear()
			if _, err := buffer.ReadFullFrom(reader, messSeedLen); err != nil {
				return nil, newError("failed to read response messSeed").Base(err)
			}

			response.MessSeed = make([]byte, messSeedLen)
			copy(response.MessSeed, buffer.Bytes())

		}

	}

	return response, nil
}

func (c *ClientSession) DecodeResponseBody(response *protocol.RequestHeader, reader io.Reader) buf.Reader {

	switch response.MessName {
	case "shake":

		var sizeParser crypto.ChunkSizeDecoder = crypto.PlainChunkSizeParser{}
		sizeParser = NewShakeSizeParser(response.MessSeed)
		var padding crypto.PaddingLengthGenerator
		//padding = sizeParser.(crypto.PaddingLengthGenerator)

		if response.Command.TransferType() == protocol.TransferTypeStream {
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
