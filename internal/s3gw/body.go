package s3gw

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Request bodies: plain, hash-checked, or aws-chunked (signed chunks or
// unsigned with a checksum trailer), plus the optional Content-MD5 and
// x-amz-checksum-* checks. Every check fails the read at EOF at the latest,
// before an object is committed.

const maxChunk = 16 << 20

// body returns the decoded request body and its length (-1 if unknown).
func (a *Auth) body(r *http.Request) (io.Reader, int64, error) {
	var rd io.Reader = r.Body
	size := r.ContentLength
	streaming := strings.HasPrefix(a.PayloadHash, "STREAMING-")
	if streaming {
		if enc := r.Header.Get("Content-Encoding"); enc != "" && !hasToken(enc, "aws-chunked") {
			return nil, 0, errf("InvalidArgument", http.StatusBadRequest, "streaming payload needs Content-Encoding aws-chunked")
		}
		n, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
		if err != nil || n < 0 {
			return nil, 0, errf("MissingContentLength", http.StatusLengthRequired, "x-amz-decoded-content-length is required for streaming uploads")
		}
		size = n
		cr := &chunkedReader{br: bufio.NewReader(r.Body), a: a, prev: a.signature,
			signed: a.PayloadHash != payloadStreamingUnsTrlr, signedTrailer: a.PayloadHash == payloadStreamingTrailer}
		if t := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Amz-Trailer"))); t != "" {
			h := newChecksum(t)
			if h == nil {
				return nil, 0, errf("InvalidRequest", http.StatusBadRequest, "unsupported trailer %q", t)
			}
			cr.trailer, cr.sum = t, h
		}
		rd = cr
	} else if a.PayloadHash != payloadUnsigned && a.PayloadHash != "" {
		want, _ := hex.DecodeString(a.PayloadHash)
		rd = &verifyReader{r: rd, h: sha256.New(), want: want,
			err: errf("XAmzContentSHA256Mismatch", http.StatusBadRequest, "the body does not match x-amz-content-sha256")}
	}
	for _, alg := range checksumAlgs {
		v := r.Header.Get("X-Amz-Checksum-" + alg)
		if v == "" {
			continue
		}
		want, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, 0, errf("InvalidRequest", http.StatusBadRequest, "bad x-amz-checksum-%s", alg)
		}
		rd = &verifyReader{r: rd, h: newChecksum("x-amz-checksum-" + alg), want: want,
			err: errf("BadDigest", http.StatusBadRequest, "the %s checksum does not match", alg)}
	}
	if v := r.Header.Get("Content-MD5"); v != "" {
		want, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(want) != md5.Size {
			return nil, 0, errf("InvalidDigest", http.StatusBadRequest, "Content-MD5 is not a base64 MD5")
		}
		rd = &verifyReader{r: rd, h: md5.New(), want: want,
			err: errf("BadDigest", http.StatusBadRequest, "the Content-MD5 does not match")}
	}
	if size >= 0 {
		rd = &lengthReader{r: rd, left: size}
	}
	return rd, size, nil
}

var checksumAlgs = []string{"crc32", "crc32c", "crc64nvme", "sha1", "sha256"}

var (
	castagnoli = crc32.MakeTable(crc32.Castagnoli)
	// CRC-64/NVME: Go's crc64 takes the reflected polynomial and already
	// inverts the initial value and the result.
	nvme = crc64.MakeTable(0x9a6c9329ac4bc9b5)
)

// newChecksum returns the hash for an x-amz-checksum-* header name.
func newChecksum(header string) hash.Hash {
	switch strings.TrimPrefix(header, "x-amz-checksum-") {
	case "crc32":
		return crc32.NewIEEE()
	case "crc32c":
		return crc32.New(castagnoli)
	case "crc64nvme":
		return crc64.New(nvme)
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	}
	return nil
}

// verifyReader hashes what passes through and fails at EOF on a mismatch.
type verifyReader struct {
	r    io.Reader
	h    hash.Hash
	want []byte
	err  error
}

func (v *verifyReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	if err == io.EOF && !bytes.Equal(v.h.Sum(nil), v.want) {
		return n, v.err
	}
	return n, err
}

// lengthReader fails if the body is shorter or longer than declared.
type lengthReader struct {
	r    io.Reader
	left int64
}

func (l *lengthReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.left -= int64(n)
	if l.left < 0 {
		return n, errf("InvalidRequest", http.StatusBadRequest, "body is longer than its declared length")
	}
	if err == io.EOF && l.left > 0 {
		return n, errf("IncompleteBody", http.StatusBadRequest, "body is shorter than its declared length")
	}
	return n, err
}

// chunkedReader decodes an aws-chunked body, checking each chunk's
// signature before releasing its data.
type chunkedReader struct {
	br            *bufio.Reader
	a             *Auth
	signed        bool
	signedTrailer bool
	trailer       string    // expected checksum trailer, if any
	sum           hash.Hash // running checksum for the trailer
	prev          string    // previous signature in the chain

	buf  []byte
	off  int
	done bool
	err  error
}

var errChunkFormat = errf("IncompleteBody", http.StatusBadRequest, "malformed aws-chunked body")

func (c *chunkedReader) Read(p []byte) (int, error) {
	for c.off == len(c.buf) {
		if c.err != nil {
			return 0, c.err
		}
		if c.done {
			return 0, io.EOF
		}
		c.err = c.next()
	}
	n := copy(p, c.buf[c.off:])
	c.off += n
	return n, nil
}

func (c *chunkedReader) next() error {
	line, err := c.line()
	if err != nil {
		return errChunkFormat
	}
	sizeHex, ext, _ := strings.Cut(line, ";")
	size, err := strconv.ParseInt(strings.TrimSpace(sizeHex), 16, 64)
	if err != nil || size < 0 || size > maxChunk {
		return errChunkFormat
	}
	sig := ""
	if v, ok := strings.CutPrefix(strings.TrimSpace(ext), "chunk-signature="); ok {
		sig = v
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(c.br, data); err != nil {
		return errChunkFormat
	}
	if size > 0 {
		var crlf [2]byte
		if _, err := io.ReadFull(c.br, crlf[:]); err != nil || string(crlf[:]) != "\r\n" {
			return errChunkFormat
		}
	}
	if c.signed {
		sum := sha256.Sum256(data)
		toSign := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.a.amzDate + "\n" + c.a.scope + "\n" + c.prev + "\n" + emptySHA256 + "\n" + hex.EncodeToString(sum[:])
		if sig == "" || hex.EncodeToString(hmacSHA256(c.a.signingKey, toSign)) != sig {
			return errf("SignatureDoesNotMatch", http.StatusForbidden, "a chunk signature does not match")
		}
		c.prev = sig
	}
	if c.sum != nil {
		c.sum.Write(data)
	}
	c.buf, c.off = data, 0
	if size == 0 {
		c.done = true
		return c.trailers()
	}
	return nil
}

// trailers reads the trailing headers after the last chunk.
func (c *chunkedReader) trailers() error {
	var canon strings.Builder
	got := map[string]string{}
	sig := ""
	for {
		line, err := c.line()
		if err == io.EOF || (err == nil && line == "") {
			break
		}
		if err != nil {
			return errChunkFormat
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return errChunkFormat
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if k == "x-amz-trailer-signature" {
			sig = v
			continue
		}
		got[k] = v
		canon.WriteString(k + ":" + v + "\n")
	}
	if c.signedTrailer {
		sum := sha256.Sum256([]byte(canon.String()))
		toSign := "AWS4-HMAC-SHA256-TRAILER\n" + c.a.amzDate + "\n" + c.a.scope + "\n" + c.prev + "\n" + hex.EncodeToString(sum[:])
		if sig == "" || hex.EncodeToString(hmacSHA256(c.a.signingKey, toSign)) != sig {
			return errf("SignatureDoesNotMatch", http.StatusForbidden, "the trailer signature does not match")
		}
	}
	if c.trailer != "" {
		v, ok := got[c.trailer]
		want, err := base64.StdEncoding.DecodeString(v)
		if !ok || err != nil {
			return errf("InvalidRequest", http.StatusBadRequest, "missing trailer %s", c.trailer)
		}
		if !bytes.Equal(c.sum.Sum(nil), want) {
			return errf("BadDigest", http.StatusBadRequest, "the %s checksum does not match", c.trailer)
		}
	}
	return nil
}

func (c *chunkedReader) line() (string, error) {
	var b []byte
	for {
		part, isPrefix, err := c.br.ReadLine()
		if err != nil {
			if err == io.EOF && len(b) > 0 {
				return string(b), nil
			}
			return "", err
		}
		b = append(b, part...)
		if len(b) > 4096 {
			return "", errors.New("line too long")
		}
		if !isPrefix {
			return string(b), nil
		}
	}
}

func hasToken(list, tok string) bool {
	for _, t := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(t), tok) {
			return true
		}
	}
	return false
}
