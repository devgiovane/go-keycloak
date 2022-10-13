package main

import (
	"context"
	"encoding/json"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

var (
	clientID = "myclient"
	clientSecret = "7b96cQ4Ea4DtwTQV5abrNirBdgDmHaeU"
)

func main() {
	tokens := make(map[string]*oauth2.Token)
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "http://localhost:8080/realms/myrealm")
	if err != nil {
		log.Fatal(err)
	}
	config := oauth2.Config{
		ClientID: clientID,
		ClientSecret: clientSecret,
		Endpoint: provider.Endpoint(),
		RedirectURL: "http://localhost:8081/auth/callback",
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}
	state := uuid.NewString()
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})
	http.HandleFunc("/auth/callback", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("state") != state {
			http.Error(writer, "Invalid state", http.StatusBadRequest)
			return
		}
		token, err := config.Exchange(ctx, request.URL.Query().Get("code"))
		if err != nil {
			http.Error(writer, "Error in code", http.StatusInternalServerError)
			return
		}
		data, err := json.Marshal(token)
		if err != nil {
			http.Error(writer, "Error in token", http.StatusInternalServerError)
			return
		}
		tokens[token.AccessToken] = token
		writer.Write(data)
 	})
	http.HandleFunc("/auth/id", func(writer http.ResponseWriter, request *http.Request) {
		token := tokens[request.URL.Query().Get("token")]
		idToken , ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(writer, "Error in id token", http.StatusInternalServerError)
			return
		}
		response := struct {
			IDToken string `json:"id_token"`
		}{
			idToken,
		}
		data, err := json.Marshal(response)
		if err != nil {
			http.Error(writer, "Error in token", http.StatusInternalServerError)
			return
		}
		writer.Write(data)
	})
	http.HandleFunc("/auth/userinfo", func(writer http.ResponseWriter, request *http.Request) {
		token := tokens[request.URL.Query().Get("token")]
		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			http.Error(writer, "Error in user info", http.StatusInternalServerError)
			return
		}
		data, err := json.Marshal(userInfo)
		if err != nil {
			http.Error(writer, "Error in token", http.StatusInternalServerError)
			return
		}
		writer.Write(data)
	})
	log.Fatal(http.ListenAndServe(":8081", nil))
}
