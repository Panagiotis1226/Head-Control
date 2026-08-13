package hsclient

import (
	"context"
	"net/http"
	"net/url"
)

// UserFilter narrows ListUsers. All fields are optional exact matches.
type UserFilter struct {
	ID    string
	Name  string
	Email string
}

// ListUsers returns users, optionally filtered. GET /api/v1/user
func (c *Client) ListUsers(ctx context.Context, filter UserFilter) ([]User, error) {
	q := url.Values{}
	if filter.ID != "" {
		q.Set("id", filter.ID)
	}
	if filter.Name != "" {
		q.Set("name", filter.Name)
	}
	if filter.Email != "" {
		q.Set("email", filter.Email)
	}
	var out struct {
		Users []User `json:"users"`
	}
	if err := c.do(ctx, http.MethodGet, "/user", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

// CreateUser creates a user. POST /api/v1/user
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	var out struct {
		User *User `json:"user"`
	}
	if err := c.do(ctx, http.MethodPost, "/user", nil, req, &out); err != nil {
		return nil, err
	}
	return out.User, nil
}

// RenameUser renames the user with numeric ID oldID.
// POST /api/v1/user/{oldId}/rename/{newName}
func (c *Client) RenameUser(ctx context.Context, oldID, newName string) (*User, error) {
	var out struct {
		User *User `json:"user"`
	}
	path := "/user/" + url.PathEscape(oldID) + "/rename/" + url.PathEscape(newName)
	if err := c.do(ctx, http.MethodPost, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return out.User, nil
}

// DeleteUser deletes the user with numeric ID id. DELETE /api/v1/user/{id}
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/user/"+url.PathEscape(id), nil, nil, nil)
}
