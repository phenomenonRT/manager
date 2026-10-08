package server

import (
	"net/http/cookiejar"
	"net/url"
)

func cookiejarNew() (*cookiejar.Jar, error) { return cookiejar.New(nil) }

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }
