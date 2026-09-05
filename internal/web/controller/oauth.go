package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/random"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/session"
)

const oauthStateKey = "OAUTH_STATE"

// OAuthController handles OIDC login and callback routes.
type OAuthController struct {
	BaseController
	settingService service.SettingService
}

func NewOAuthController(g *gin.RouterGroup, settingService service.SettingService) *OAuthController {
	a := &OAuthController{settingService: settingService}
	g.GET("/oauth/login", a.oauthLogin)
	g.GET("/oauth/callback", a.oauthCallback)
	g.POST("/getOAuthEnable", a.getOAuthEnable)
	return a
}

func (a *OAuthController) getOAuthEnable(c *gin.Context) {
	enabled, _ := a.isOAuthConfigured()
	jsonObj(c, enabled, nil)
}

func (a *OAuthController) isOAuthConfigured() (bool, error) {
	enable, err := a.settingService.GetOauthEnable()
	if err != nil {
		return false, err
	}
	if !enable {
		return false, nil
	}
	issuer, _ := a.settingService.GetOauthIssuer()
	clientID, _ := a.settingService.GetOauthClientID()
	clientSecret, _ := a.settingService.GetOauthClientSecret()
	return issuer != "" && clientID != "" && clientSecret != "", nil
}

func (a *OAuthController) getOAuthConfig() (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	issuer, err := a.settingService.GetOauthIssuer()
	if err != nil || issuer == "" {
		return nil, nil, errors.New("OAuth issuer not configured")
	}
	clientID, err := a.settingService.GetOauthClientID()
	if err != nil || clientID == "" {
		return nil, nil, errors.New("OAuth client ID not configured")
	}
	clientSecret, err := a.settingService.GetOauthClientSecret()
	if err != nil || clientSecret == "" {
		return nil, nil, errors.New("OAuth client secret not configured")
	}

	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("OIDC provider discovery failed: %w", err)
	}

	scopesStr, _ := a.settingService.GetOauthScopes()
	scopes := []string{oidc.ScopeOpenID}
	if scopesStr != "" {
		for _, s := range strings.Split(scopesStr, ",") {
			scopes = append(scopes, strings.TrimSpace(s))
		}
	}

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	return oauthConfig, verifier, nil
}

func (a *OAuthController) oauthLogin(c *gin.Context) {
	ok, _ := a.isOAuthConfigured()
	if !ok {
		pureJsonMsg(c, http.StatusOK, false, "OAuth is not configured")
		return
	}

	oauthConfig, _, err := a.getOAuthConfig()
	if err != nil {
		logger.Warning("OAuth config error:", err)
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.oauthConfigError"))
		return
	}

	state, err := generateOAuthState()
	if err != nil {
		logger.Warning("OAuth state generation error:", err)
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.oauthError"))
		return
	}

	s := sessions.Default(c)
	s.Set(oauthStateKey, state)
	if err := s.Save(); err != nil {
		logger.Warning("OAuth state save error:", err)
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.oauthError"))
		return
	}

	basePath := c.GetString("base_path")
	oauthConfig.RedirectURL = buildRedirectURI(c, basePath)

	c.Redirect(http.StatusTemporaryRedirect, oauthConfig.AuthCodeURL(state))
}

func (a *OAuthController) oauthCallback(c *gin.Context) {
	basePath := c.GetString("base_path")
	loginURL := basePath

	s := sessions.Default(c)
	expectedState, _ := s.Get(oauthStateKey).(string)
	s.Delete(oauthStateKey)
	_ = s.Save()

	stateParam := c.Query("state")
	if stateParam == "" || stateParam != expectedState {
		logger.Warning("OAuth state mismatch")
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=state_mismatch")
		return
	}

	if errMsg := c.Query("error"); errMsg != "" {
		logger.Warningf("OAuth provider error: %s", errMsg)
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error="+errMsg)
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=no_code")
		return
	}

	oauthConfig, verifier, err := a.getOAuthConfig()
	if err != nil {
		logger.Warning("OAuth config error:", err)
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=config")
		return
	}
	oauthConfig.RedirectURL = buildRedirectURI(c, basePath)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Warning("OAuth token exchange error:", err)
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=token_exchange")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		logger.Warning("OAuth response missing id_token")
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=no_id_token")
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Warning("OIDC token verification error:", err)
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=invalid_token")
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		logger.Warning("OIDC claims parse error:", err)
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=claims")
		return
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		logger.Warning("OIDC token missing sub claim")
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=no_subject")
		return
	}

	user, err := a.findOrCreateOIDCUser(claims, subject)
	if err != nil {
		logger.Warning("OAuth user lookup error:", err)
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=user_create")
		return
	}

	if err := session.SetLoginUser(c, user); err != nil {
		logger.Warning("OAuth session error:", err)
		c.Redirect(http.StatusTemporaryRedirect, loginURL+"?error=session")
		return
	}

	logger.Infof("OIDC user %s logged in via SSO", subject)
	c.Redirect(http.StatusTemporaryRedirect, basePath+"panel/")
}

func (a *OAuthController) findOrCreateOIDCUser(claims map[string]any, subject string) (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}
	err := db.Where("oidc_subject = ?", subject).First(user).Error
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	usernameClaim, _ := a.settingService.GetOauthUsernameClaim()
	if usernameClaim == "" {
		usernameClaim = "email"
	}
	username, _ := claims[usernameClaim].(string)
	if username == "" {
		username = subject
	}

	baseUsername := username
	for i := 1; ; i++ {
		var count int64
		db.Model(&model.User{}).Where("username = ?", username).Count(&count)
		if count == 0 {
			break
		}
		username = fmt.Sprintf("%s_%d", baseUsername, i)
	}

	user = &model.User{
		Username:    username,
		Password:    "$2a$10$" + random.Seq(53),
		OidcSubject: subject,
	}
	return user, db.Create(user).Error
}

func buildRedirectURI(c *gin.Context, basePath string) string {
	domain := ""
	if svc, ok := c.Get("settingService"); ok {
		if ss, ok2 := svc.(*service.SettingService); ok2 {
			domain, _ = ss.GetWebDomain()
		}
	}
	if domain == "" {
		domain = c.Request.Host
	}
	scheme := "https"
	if c.Request.TLS == nil {
		if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s://%s%soauth/callback", scheme, domain, basePath)
}

func generateOAuthState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
