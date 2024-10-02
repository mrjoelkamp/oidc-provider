package op

import (
	"sync"
	"time"
)

type Token struct {
	IDToken string `json:"id_token"`
	Issued  time.Time
}

type AuthCode struct {
	RequestID string
	Code      string
	Issued    time.Time
}

type Storage struct {
	lock     sync.Mutex
	requests map[string]*AuthRequest
	codes    map[string]*AuthCode
	tokens   map[string]*Token
}

func NewStorage() *Storage {
	return &Storage{
		requests: make(map[string]*AuthRequest),
		codes:    make(map[string]*AuthCode),
		tokens:   make(map[string]*Token),
	}
}
