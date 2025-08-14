package memory

import (
	"context"
	"fmt"
	"time"

	"core/ids"
	"guard"

	"golang.org/x/crypto/bcrypt"
)

// Implement UserManager interface

// CreateUser creates a new user with the given details.
func (s *Service) CreateUser(ctx context.Context, username, email, password string, roles []string) (*guard.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists
	if _, exists := s.usersByName[username]; exists {
		return nil, fmt.Errorf("%w: username '%s' already exists", ErrUserExists, username)
	}

	if _, exists := s.usersByEmail[email]; exists {
		return nil, fmt.Errorf("%w: email '%s' already exists", ErrUserExists, email)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), s.config.BCryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate user ID
	userID := ids.MustUUID()

	// Create user
	user := &guard.User{
		ID:       userID,
		Username: username,
		Email:    email,
		IsActive: true,
		Roles:    roles,
		Metadata: map[string]string{
			"password_hash": string(hashedPassword),
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Store user
	s.users[userID] = user
	s.usersByName[username] = userID
	s.usersByEmail[email] = userID
	s.userRoles[userID] = roles

	// Return copy without password hash
	result := *user
	result.Metadata = make(map[string]string)
	for k, v := range user.Metadata {
		if k != "password_hash" {
			result.Metadata[k] = v
		}
	}

	return &result, nil
}

// GetUser retrieves a user by ID.
func (s *Service) GetUser(ctx context.Context, userID string) (*guard.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}

	// Return a copy without password hash
	result := *user
	result.Metadata = make(map[string]string)
	for k, v := range user.Metadata {
		if k != "password_hash" {
			result.Metadata[k] = v
		}
	}

	return &result, nil
}

// GetUserByUsername retrieves a user by username.
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*guard.User, error) {
	s.mu.RLock()
	userID, exists := s.usersByName[username]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrUserNotFound
	}

	return s.GetUser(ctx, userID)
}

// GetUserByEmail retrieves a user by email.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*guard.User, error) {
	s.mu.RLock()
	userID, exists := s.usersByEmail[email]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrUserNotFound
	}

	return s.GetUser(ctx, userID)
}

// UpdateUser updates user information.
func (s *Service) UpdateUser(ctx context.Context, userID string, updates guard.UserUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	// Update fields
	if updates.Email != nil {
		// Check if new email already exists
		if existingUserID, exists := s.usersByEmail[*updates.Email]; exists && existingUserID != userID {
			return fmt.Errorf("%w: email '%s' already exists", ErrUserExists, *updates.Email)
		}

		// Update email mappings
		delete(s.usersByEmail, user.Email)
		user.Email = *updates.Email
		s.usersByEmail[*updates.Email] = userID
	}

	if updates.FirstName != nil {
		user.FirstName = *updates.FirstName
	}

	if updates.LastName != nil {
		user.LastName = *updates.LastName
	}

	if updates.IsActive != nil {
		user.IsActive = *updates.IsActive
	}

	if updates.Roles != nil {
		user.Roles = updates.Roles
		s.userRoles[userID] = updates.Roles
	}

	if updates.Metadata != nil {
		if user.Metadata == nil {
			user.Metadata = make(map[string]string)
		}
		for k, v := range updates.Metadata {
			user.Metadata[k] = v
		}
	}

	user.UpdatedAt = time.Now()
	return nil
}

// DeleteUser deletes a user.
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	// Remove from all mappings
	delete(s.users, userID)
	delete(s.usersByName, user.Username)
	delete(s.usersByEmail, user.Email)
	delete(s.userRoles, userID)

	return nil
}

// ChangePassword changes a user's password.
func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	// Verify old password
	currentHash := user.Metadata["password_hash"]
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.config.BCryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if user.Metadata == nil {
		user.Metadata = make(map[string]string)
	}
	user.Metadata["password_hash"] = string(hashedPassword)
	user.UpdatedAt = time.Now()

	return nil
}
