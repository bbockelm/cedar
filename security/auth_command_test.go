package security

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
)

// TestAuthCommandInClientAd tests that AuthCommand is included in client security ClassAd when set
func TestAuthCommandInClientAd(t *testing.T) {
	t.Run("with_auth_command", func(t *testing.T) {
		config := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS, AuthToken},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			Command:        commands.DC_SEC_QUERY,
			AuthCommand:    commands.DC_NOP_WRITE,
		}

		auth := &Authenticator{
			config: config,
		}

		ad := auth.createClientSecurityAd()

		// Verify Command is set
		if cmd, ok := ad.EvaluateAttrInt("Command"); !ok {
			t.Error("Expected Command attribute to be set")
		} else if int(cmd) != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, cmd)
		}

		// Verify AuthCommand is set
		if authCmd, ok := ad.EvaluateAttrInt("AuthCommand"); !ok {
			t.Error("Expected AuthCommand attribute to be set")
		} else if int(authCmd) != commands.DC_NOP_WRITE {
			t.Errorf("Expected AuthCommand to be %d (DC_NOP_WRITE), got %d", commands.DC_NOP_WRITE, authCmd)
		}
	})

	t.Run("without_auth_command", func(t *testing.T) {
		config := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			Command:        commands.DC_SEC_QUERY,
			// No AuthCommand set
		}

		auth := &Authenticator{
			config: config,
		}

		ad := auth.createClientSecurityAd()

		// Verify Command is set
		if cmd, ok := ad.EvaluateAttrInt("Command"); !ok {
			t.Error("Expected Command attribute to be set")
		} else if int(cmd) != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, cmd)
		}

		// Verify AuthCommand is NOT set (or is undefined)
		if _, ok := ad.EvaluateAttrInt("AuthCommand"); ok {
			t.Error("Expected AuthCommand attribute to not be set when AuthCommand is 0")
		}
	})

	t.Run("default_command_without_explicit_command", func(t *testing.T) {
		config := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			// No Command or AuthCommand set - should default to DC_AUTHENTICATE
		}

		auth := &Authenticator{
			config: config,
		}

		ad := auth.createClientSecurityAd()

		// Verify Command defaults to DC_AUTHENTICATE
		if cmd, ok := ad.EvaluateAttrInt("Command"); !ok {
			t.Error("Expected Command attribute to be set")
		} else if int(cmd) != commands.DC_AUTHENTICATE {
			t.Errorf("Expected Command to default to %d (DC_AUTHENTICATE), got %d", commands.DC_AUTHENTICATE, cmd)
		}

		// Verify AuthCommand is NOT set
		if _, ok := ad.EvaluateAttrInt("AuthCommand"); ok {
			t.Error("Expected AuthCommand attribute to not be set when not specified")
		}
	})
}

// TestAuthCommandParsing tests that AuthCommand is correctly parsed from ClassAds
func TestAuthCommandParsing(t *testing.T) {
	t.Run("parse_with_auth_command", func(t *testing.T) {
		ad := classad.New()
		_ = ad.Set("Command", commands.DC_SEC_QUERY)
		_ = ad.Set("AuthCommand", commands.DC_NOP_WRITE)
		_ = ad.Set("AuthMethods", "FS")
		_ = ad.Set("CryptoMethods", "AES")
		_ = ad.Set("Authentication", "OPTIONAL")
		_ = ad.Set("Encryption", "OPTIONAL")

		auth := &Authenticator{}
		config := auth.parseServerSecurityAd(ad)

		if config.Command != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, config.Command)
		}

		if config.AuthCommand != commands.DC_NOP_WRITE {
			t.Errorf("Expected AuthCommand to be %d (DC_NOP_WRITE), got %d", commands.DC_NOP_WRITE, config.AuthCommand)
		}
	})

	t.Run("parse_without_auth_command", func(t *testing.T) {
		ad := classad.New()
		_ = ad.Set("Command", commands.DC_SEC_QUERY)
		_ = ad.Set("AuthMethods", "FS")
		_ = ad.Set("CryptoMethods", "AES")

		auth := &Authenticator{}
		config := auth.parseServerSecurityAd(ad)

		if config.Command != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, config.Command)
		}

		if config.AuthCommand != 0 {
			t.Errorf("Expected AuthCommand to be 0 (not set), got %d", config.AuthCommand)
		}
	})
}
