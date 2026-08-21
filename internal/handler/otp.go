package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/pkg/response"
)

// OTPSend handles POST /api/v1/auth/otp/send
func (h *AuthHandler) OTPSend(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "valid email is required")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	respondSent := func() { response.OK(c, gin.H{"status": "sent"}) }
	if h.Config == nil || !h.Config.OTPEnabled || h.Email == nil || !h.Email.IsConfigured() {
		// Indistinguishable from a real delivery. Production validation
		// prevents this configuration; the closed response avoids account
		// enumeration during maintenance or partial outages.
		respondSent()
		return
	}

	if !h.Config.OTPOpenRegistration {
		allowed, err := h.Store.IsOTPRecipientKnown(c, email)
		if err != nil {
			response.Internal(c)
			return
		}
		if !allowed {
			parts := strings.Split(email, "@")
			domain := ""
			if len(parts) == 2 {
				domain = parts[1]
			}
			for _, approved := range h.Config.OTPAllowedDomains {
				if strings.EqualFold(domain, approved) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			respondSent()
			return
		}
	}

	code := generateOTPCode()
	codeHash := hashOTPCode(code, h.Config.OTPPepper)

	otp := &model.OTPCode{
		Email:     email,
		CodeHash:  codeHash,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	created, err := h.Store.CreateOTPCodeWithLimit(c, otp, 3)
	if err != nil {
		response.Internal(c)
		return
	}
	if !created {
		respondSent()
		return
	}

	h.Email.SendOTPCode(email, code)

	respondSent()
}

// OTPVerify handles POST /api/v1/auth/otp/verify
func (h *AuthHandler) OTPVerify(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		Code  string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "email and code are required")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	code := strings.TrimSpace(req.Code)
	if h.Config == nil || !h.Config.OTPEnabled {
		response.Unauthorized(c, "invalid or expired code")
		return
	}

	candidateVerifier := hashOTPCode(code, h.Config.OTPPepper)
	dummyVerifier := hashOTPCode("", h.Config.OTPPepper)
	otp, codeMatch, err := h.Store.ConsumeOTPCode(c, email, candidateVerifier, dummyVerifier)
	if err != nil {
		response.Internal(c)
		return
	}
	if !codeMatch || otp == nil {
		response.Unauthorized(c, "invalid or expired code")
		return
	}

	// Upsert user (create on first login)
	user := &model.User{Email: email}
	if err := h.Store.UpsertUser(c, user); err != nil {
		response.Internal(c)
		return
	}
	user, err = h.Store.FindUserByEmail(c, email)
	if err != nil {
		response.Internal(c)
		return
	}

	// Auto-promote if email is in ADMIN_EMAILS
	if h.Config.IsAdminEmail(user.Email) && user.Role == model.RoleUser {
		_ = h.Store.SetUserRole(c, user.ID, model.RoleAdmin)
		user.Role = model.RoleAdmin
	}

	// Welcome email for new users
	if h.Email != nil && time.Since(user.CreatedAt) < time.Minute {
		h.Email.SendWelcome(user.Email, user.Name)
	}

	h.issueSession(c, user)

	h.Store.Audit(c, &model.AuditLog{
		Entity: "session", EntityID: user.ID, Action: "login",
		ActorType: "otp", ActorID: user.ID, IPAddress: c.ClientIP(),
		Changes: map[string]any{"email": user.Email},
	})

	response.OK(c, gin.H{
		"status": "ok", "email": user.Email, "name": user.Name,
		"is_admin": user.IsAdmin(), "role": user.Role,
	})
}

func generateOTPCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", n.Int64())
}

func hashOTPCode(code, pepper string) string {
	h := hmac.New(sha256.New, []byte(pepper))
	_, _ = h.Write([]byte(code))
	return hex.EncodeToString(h.Sum(nil))
}
