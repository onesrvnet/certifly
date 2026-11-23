package host

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Namespace of the signatures a host makes for certifly.
const Namespace = "certifly-host@certifly"

// SignSSHSIG makes an armored SSH signature (OpenSSH PROTOCOL.sshsig, what `ssh-keygen -Y sign`
// writes) over message with sha512.
func SignSSHSIG(signer ssh.Signer, namespace string, message []byte) (string, error) {
	sum := sha512.Sum512(message)
	toSign := bytes.NewBufferString("SSHSIG")
	toSign.Write(ssh.Marshal(struct {
		Namespace, Reserved, Hash string
		Digest                    []byte
	}{namespace, "", "sha512", sum[:]}))

	var sig *ssh.Signature
	var err error
	if as, ok := signer.(ssh.AlgorithmSigner); ok && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		sig, err = as.SignWithAlgorithm(rand.Reader, toSign.Bytes(), ssh.KeyAlgoRSASHA512)
	} else {
		sig, err = signer.Sign(rand.Reader, toSign.Bytes())
	}
	if err != nil {
		return "", err
	}
	blob := bytes.NewBufferString("SSHSIG")
	blob.Write(ssh.Marshal(struct {
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		Hash      string
		Signature []byte
	}{1, signer.PublicKey().Marshal(), namespace, "", "sha512", ssh.Marshal(sig)}))
	if blob.Len() == 0 {
		return "", errors.New("empty signature")
	}
	enc := base64.StdEncoding.EncodeToString(blob.Bytes())
	var out strings.Builder
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n-----END SSH SIGNATURE-----\n")
	return out.String(), nil
}
