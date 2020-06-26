// +build !confonly

package vless

import (
	"strings"
	"sync"

	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/uuid"
)

type Validator struct {
	sync.RWMutex
	users map[uuid.UUID]*protocol.MemoryUser
	email map[string]*protocol.MemoryUser
}

func NewValidator() *Validator {
	return &Validator{
		users: make(map[uuid.UUID]*protocol.MemoryUser, 8),
		email: make(map[string]*protocol.MemoryUser, 8),
	}
}

func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	if len(u.Email) > 0 {
		e := strings.ToLower(u.Email)
		_, found := v.email[e]
		if found {
			return newError("User ", u.Email, " already exists.")
		}
		v.email[e] = u
	}
	v.users[u.Account.(*MemoryAccount).ID.UUID()] = u
	return nil
}

func (v *Validator) Del(e string) error {
	v.Lock()
	defer v.Unlock()

	if e == "" {
		return newError("Email must not be empty.")
	}
	e = strings.ToLower(e)
	u, found := v.email[e]
	if !found {
		return newError("User ", e, " not found.")
	}
	delete(v.users, u.Account.(*MemoryAccount).ID.UUID())
	delete(v.email, e)
	return nil
}

func (v *Validator) Get(id uuid.UUID) *protocol.MemoryUser {
	v.RLock()
	defer v.RUnlock()

	return v.users[id]
}
