package arc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestARCSealSingleHop(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	sealer := NewSealer("xeron.be", "xeronmx", privKey)

	originalMsg := "From: sender@example.com\r\n" +
		"To: recipient@xeron.be\r\n" +
		"Subject: Test ARC Message\r\n" +
		"Date: Fri, 04 Sep 2026 20:00:00 +0000\r\n" +
		"Message-ID: <test1234@example.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"\r\n" +
		"This is the body of the test message.\r\n"

	var out bytes.Buffer
	err = sealer.Seal(&out, strings.NewReader(originalMsg), "mx.xeron.be", "spf=pass smtp.mailfrom=sender@example.com; dkim=pass; dmarc=pass", "none")
	if err != nil {
		t.Fatalf("sealer.Seal: %v", err)
	}

	sealedStr := out.String()

	if !strings.Contains(sealedStr, "ARC-Seal: i=1;") {
		t.Errorf("sealed output missing ARC-Seal i=1: %s", sealedStr)
	}
	if !strings.Contains(sealedStr, "ARC-Message-Signature: i=1;") {
		t.Errorf("sealed output missing ARC-Message-Signature i=1: %s", sealedStr)
	}
	if !strings.Contains(sealedStr, "ARC-Authentication-Results: i=1; mx.xeron.be; spf=pass") {
		t.Errorf("sealed output missing ARC-Authentication-Results i=1: %s", sealedStr)
	}
	if !strings.Contains(sealedStr, "This is the body of the test message.") {
		t.Errorf("sealed output missing original body: %s", sealedStr)
	}

	idxAS := strings.Index(sealedStr, "ARC-Seal:")
	idxAMS := strings.Index(sealedStr, "ARC-Message-Signature:")
	idxAAR := strings.Index(sealedStr, "ARC-Authentication-Results:")
	idxFrom := strings.Index(sealedStr, "From: sender@example.com")

	if !(idxAS < idxAMS && idxAMS < idxAAR && idxAAR < idxFrom) {
		t.Errorf("headers not in expected prepended order: AS=%d, AMS=%d, AAR=%d, From=%d",
			idxAS, idxAMS, idxAAR, idxFrom)
	}
}

func TestARCSealIncrementsInstance(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	sealer := NewSealer("xeron.be", "xeronmx", privKey)

	msgWithHop1 := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=prev.com; s=s1; b=fake\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=prev.com; s=s1; b=fake\r\n" +
		"ARC-Authentication-Results: i=1; prev.com; spf=pass\r\n" +
		"From: sender@example.com\r\n" +
		"To: recipient@xeron.be\r\n" +
		"Subject: Multi-hop ARC\r\n" +
		"\r\n" +
		"Hello multi-hop.\r\n"

	var out bytes.Buffer
	err = sealer.Seal(&out, strings.NewReader(msgWithHop1), "mx.xeron.be", "spf=pass; dkim=pass", "")
	if err != nil {
		t.Fatalf("sealer.Seal multi-hop: %v", err)
	}

	sealedStr := out.String()
	if !strings.Contains(sealedStr, "ARC-Seal: i=2;") {
		t.Errorf("expected ARC-Seal i=2, got: %s", sealedStr)
	}
	if !strings.Contains(sealedStr, "ARC-Message-Signature: i=2;") {
		t.Errorf("expected ARC-Message-Signature i=2, got: %s", sealedStr)
	}
	if !strings.Contains(sealedStr, "cv=pass") {
		t.Errorf("expected cv=pass for second hop, got: %s", sealedStr)
	}
}
