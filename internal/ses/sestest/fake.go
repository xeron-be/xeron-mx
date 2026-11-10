package sestest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/xeron-be/xeron-mx/internal/ses"
)

type Fake struct {
	mu         sync.Mutex
	identities map[string]*ses.Identity

	Err error

	Creates []string
	Gets    []string
	Deletes []string
}

func New() *Fake { return &Fake{identities: map[string]*ses.Identity{}} }

func (f *Fake) Put(name, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[name] = &ses.Identity{
		Name: name, Status: status, VerifiedForSending: status == ses.StatusSuccess,
		DKIMTokens: tokens(name),
	}
}

func (f *Fake) SetStatus(name, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.identities[name]; ok {
		id.Status = status
		id.VerifiedForSending = status == ses.StatusSuccess
	}
}

func (f *Fake) Has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.identities[name]
	return ok
}

func (f *Fake) CreateIdentity(_ context.Context, domain string) (*ses.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Creates = append(f.Creates, domain)
	if f.Err != nil {
		return nil, f.Err
	}
	if _, ok := f.identities[domain]; ok {
		return nil, &ses.APIError{StatusCode: 400, Code: "AlreadyExistsException"}
	}
	id := &ses.Identity{Name: domain, Status: ses.StatusPending, DKIMTokens: tokens(domain)}
	f.identities[domain] = id
	c := *id
	return &c, nil
}

func (f *Fake) GetIdentity(_ context.Context, domain string) (*ses.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Gets = append(f.Gets, domain)
	if f.Err != nil {
		return nil, f.Err
	}
	id, ok := f.identities[domain]
	if !ok {
		return nil, &ses.APIError{StatusCode: 404, Code: "NotFoundException"}
	}
	c := *id
	return &c, nil
}

func (f *Fake) DeleteIdentity(_ context.Context, domain string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Deletes = append(f.Deletes, domain)
	if f.Err != nil {
		return f.Err
	}
	if _, ok := f.identities[domain]; !ok {
		return &ses.APIError{StatusCode: 404, Code: "NotFoundException"}
	}
	delete(f.identities, domain)
	return nil
}

func tokens(domain string) []string {
	base := strings.ReplaceAll(domain, ".", "")
	return []string{fmt.Sprintf("%sa1", base), fmt.Sprintf("%sb2", base), fmt.Sprintf("%sc3", base)}
}
