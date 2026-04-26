package encrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type Service struct {
	client *kms.Client
	keyARN string
}

func New(awsCfg aws.Config, keyARN string) *Service {
	return &Service{
		client: kms.NewFromConfig(awsCfg),
		keyARN: keyARN,
	}
}

func (s *Service) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	// Ask KMS to generate a 256-bit data key
	out, err := s.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &s.keyARN,
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, fmt.Errorf("generating data key: %w", err)
	}

	// AES-256-GCM encrypt the plaintext with the ephemeral plaintext key
	block, err := aes.NewCipher(out.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Seal appends ciphertext to nonce, giving us [nonce][ciphertext+tag]
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)

	// Pack: [4 bytes: len(encKey)][encKey][sealed]
	encKey := out.CiphertextBlob
	blob := make([]byte, 4+len(encKey)+len(sealed))
	binary.BigEndian.PutUint32(blob[0:4], uint32(len(encKey)))
	copy(blob[4:], encKey)
	copy(blob[4+len(encKey):], sealed)

	return blob, nil
}

func (s *Service) Decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("blob too short")
	}

	// Unpack
	encKeyLen := int(binary.BigEndian.Uint32(blob[0:4]))
	if len(blob) < 4+encKeyLen {
		return nil, fmt.Errorf("blob malformed: declared key length exceeds blob size")
	}
	encKey := blob[4 : 4+encKeyLen]
	sealed := blob[4+encKeyLen:]

	// Decrypt the data key with KMS
	decOut, err := s.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: encKey,
		KeyId:          &s.keyARN,
	})
	if err != nil {
		return nil, fmt.Errorf("decrypting data key: %w", err)
	}

	// AES-256-GCM decrypt the ciphertext
	block, err := aes.NewCipher(decOut.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("sealed payload too short")
	}

	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting ciphertext: %w", err)
	}

	return plaintext, nil
}
