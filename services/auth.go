package services

import (
	"encoding/json"
	"fmt"

	"git.difuse.io/Difuse/kalmia/config"
	"git.difuse.io/Difuse/kalmia/db/models"
	"git.difuse.io/Difuse/kalmia/utils"
	"gorm.io/gorm"
)

type AuthService struct {
	DB *gorm.DB
}

func NewAuthService(db *gorm.DB) *AuthService {
	return &AuthService{DB: db}
}

func (service *AuthService) GetUsers() ([]models.User, string, error) {
	var users []models.User

	if err := service.DB.Find(&users).Error; err != nil {
		return nil, "failed_to_get_users", err
	}

	return users, "", nil
}

func (service *AuthService) CreateJWT(username, password string) (map[string]interface{}, string, error) {
	var user models.User

	if err := service.DB.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, "user_not_found", err
	}

	if !utils.CheckPasswordHash(password, user.Password) {
		return nil, "invalid_password", fmt.Errorf("wrong_password")
	}

	tokenString, expiry, err := utils.GenerateJWTAccessToken(user.ID, user.Username, user.Email, user.Photo, user.Admin, user.Permissions)
	if err != nil {
		return nil, "failed_to_generate_jwt", err
	}

	newToken := models.Token{
		UserID: user.ID,
		Token:  tokenString,
		Expiry: expiry,
	}

	if err := service.DB.Create(&newToken).Error; err != nil {
		return nil, "failed_to_create_token", err
	}

	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		service.DB.Where("token = ?", tokenString).Delete(&models.Token{})
		return nil, "invalid_jwt_created", err
	}

	return map[string]interface{}{
		"token":       tokenString,
		"expiry":      claims.ExpiresAt.Time.String(),
		"email":       claims.Email,
		"username":    claims.Username,
		"photo":       claims.Photo,
		"userId":      claims.UserId,
		"admin":       user.Admin,
		"permissions": claims.Permissions,
	}, "", nil
}

func (service *AuthService) VerifyTokenInDb(token string, needAdmin bool) bool {
	var tokenRecord models.Token

	query := service.DB.Joins("JOIN users ON users.id = tokens.user_id").Where("tokens.token = ?", token).First(&tokenRecord)
	if query.Error != nil {
		return false
	}

	if needAdmin {
		var user models.User
		if err := service.DB.Where("id = ?", tokenRecord.UserID).First(&user).Error; err != nil {
			return false
		}
		if !user.Admin {
			return false
		}
	}

	_, err := utils.ValidateJWT(token)

	return err == nil
}

func (service *AuthService) IsTokenAdmin(token string) bool {
	var tokenRecord models.Token

	query := service.DB.
		Joins("JOIN users ON users.id = tokens.user_id").
		Where("tokens.token = ?", token).
		Select("tokens.user_id").
		First(&tokenRecord)

	if query.Error != nil {
		return false
	}

	var user models.User
	if err := service.DB.Where("id = ?", tokenRecord.UserID).First(&user).Error; err != nil {
		return false
	}

	return user.Admin
}

func (service *AuthService) GetUserPermissions(token string) ([]string, string, error) {
	user, err := service.GetUserFromToken(token)
	if err != nil {
		return nil, "failed_to_get_user", err
	}

	var permissions []string
	err = json.Unmarshal([]byte(user.Permissions), &permissions)
	if err != nil {
		return nil, "failed to parse permissions", err
	}

	return permissions, "", nil
}

func (service *AuthService) GetUserFromToken(token string) (models.User, error) {
	var tokenRecord models.Token

	query := service.DB.Where("token = ?", token).First(&tokenRecord)
	if query.Error != nil {
		return models.User{}, query.Error
	}

	var user models.User

	if err := service.DB.Where("id = ?", tokenRecord.UserID).First(&user).Error; err != nil {
		return models.User{}, err
	}

	return user, nil
}

func (service *AuthService) CreateUser(username, email, password string, admin bool, permissions []string) (string, error) {
	hashedPassword, err := utils.HashPassword(password)

	if err != nil {
		return "failed_to_hash_password", err
	}

	if len(permissions) == 0 {
		permissions = append(permissions, "read")
	}

	jsonPermissions, err := json.Marshal(permissions)

	if err != nil {
		return "failed_to_marshal_permissions", err
	}

	user := models.User{
		Username:    username,
		Email:       email,
		Password:    hashedPassword,
		Admin:       admin,
		Permissions: string(jsonPermissions),
	}

	if err := service.DB.Create(&user).Error; err != nil {
		return "failed_to_create_user", err
	}

	return "", nil
}

func (service *AuthService) EditUser(id uint, username, email, password, photo string, admin int, permissions []string) (string, error) {
	var user models.User

	if err := service.DB.Where("id = ?", id).First(&user).Error; err != nil {
		return "user_not_found", err
	}

	if username != "" {
		user.Username = username
	}

	if email != "" {
		user.Email = email
	}

	if password != "" {
		hashedPassword, err := utils.HashPassword(password)
		if err != nil {
			return "failed_to_hash_password", err
		}

		user.Password = hashedPassword
	}

	if photo != "" {
		user.Photo = photo
	}

	if admin == 0 {
		user.Admin = false
	} else {
		user.Admin = true
	}

	if len(permissions) > 0 {
		jsonPermissions, err := json.Marshal(permissions)

		if err != nil {
			return "failed_to_marshal_permissions", err
		}

		user.Permissions = string(jsonPermissions)
	}

	if err := service.DB.Save(&user).Error; err != nil {
		return "failed_to_edit_user", err
	}

	return "", nil
}

func (service *AuthService) DeleteUser(username string) (string, error) {
	var user models.User

	if err := service.DB.Where("username = ?", username).First(&user).Error; err != nil {
		return "user_not_found", err
	}

	if err := service.DB.Delete(&user).Error; err != nil {
		return "failed_to_delete_user", err
	}

	return "", nil
}

func (service *AuthService) GetUser(id uint) (models.User, string, error) {
	var user models.User

	if err := service.DB.Where("id = ?", id).First(&user).Error; err != nil {
		return models.User{}, "user_not_found", err
	}

	return user, "", nil
}

func (service *AuthService) CreateJWTFromEmail(email string) (string, error) {
	var user models.User

	if err := service.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return "", fmt.Errorf("user_not_found: %w", err)
	}

	tokenString, expiry, err := utils.GenerateJWTAccessToken(user.ID, user.Username, user.Email, user.Photo, user.Admin, user.Permissions)
	if err != nil {
		return "", fmt.Errorf("failed_to_generate_jwt: %w", err)
	}

	newToken := models.Token{
		UserID: user.ID,
		Token:  tokenString,
		Expiry: expiry,
	}

	if err := service.DB.Create(&newToken).Error; err != nil {
		return "", fmt.Errorf("failed_to_create_token: %w", err)
	}

	_, err = utils.ValidateJWT(tokenString)
	if err != nil {
		service.DB.Where("token = ?", tokenString).Delete(&models.Token{})
		return "", fmt.Errorf("invalid_jwt_created: %w", err)
	}

	return tokenString, nil
}

func (service *AuthService) RefreshJWT(token string) (string, string, error) {
	claims, err := utils.ValidateJWT(token)
	if err != nil {
		return "", "invalid_jwt", err
	}

	userId, err := utils.StringToUint(claims.UserId)
	if err != nil {
		return "", "failed_to_convert_user_id", err
	}

	permissionsJSON, err := json.Marshal(claims.Permissions)

	if err != nil {
		return "", "failed_to_marshal_permissions", err
	}

	newToken, expiry, err := utils.GenerateJWTAccessToken(userId, claims.Username, claims.Email, claims.Photo, claims.IsAdmin, string(permissionsJSON))
	if err != nil {
		return "", "failed_to_generate_new_jwt", err
	}

	var tokenRecord models.Token

	if err := service.DB.Where("token = ?", token).First(&tokenRecord).Error; err != nil {
		return "", "token_not_found", err
	}

	tokenRecord.Token = newToken
	tokenRecord.Expiry = expiry

	if err := service.DB.Save(&tokenRecord).Error; err != nil {
		return "", "failed_to_update_token", err
	}

	return newToken, "", nil
}

func (service *AuthService) ValidateJWT(token string) (map[string]interface{}, string, error) {
	var tokenRecord models.Token

	if err := service.DB.Where("token = ?", token).First(&tokenRecord).Error; err != nil {
		return nil, "token_not_found", err
	}

	claims, err := utils.ValidateJWT(token)

	if err != nil {
		return nil, "invalid_jwt", err
	}

	return map[string]interface{}{
		"token":    token,
		"email":    claims.Email,
		"username": claims.Username,
		"photo":    claims.Photo,
		"expiry":   claims.ExpiresAt.Time.String(),
		"admin":    claims.IsAdmin,
		"userId":   claims.UserId,
	}, "", nil
}

func (service *AuthService) RevokeJWT(token string) (string, error) {
	_, err := utils.ValidateJWT(token)

	if err != nil {
		return "invalid_jwt", err
	}

	var tokenRecord models.Token

	if err := service.DB.Where("token = ?", token).First(&tokenRecord).Error; err != nil {
		return "token_not_found", err
	}

	if err := service.DB.Delete(&tokenRecord).Error; err != nil {
		return "failed_to_delete_token", err
	}

	return "", nil
}

func (service *AuthService) FindUserByEmail(email string) (models.User, error) {
	var user models.User

	if err := service.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return models.User{}, fmt.Errorf("user_not_found: %w", err)
	}

	return user, nil
}

func (service *AuthService) OAuthProviders() []string {
	config := config.ParsedConfig

	var providers []string

	if config.MicrosoftOAuth.ClientSecret != "" {
		providers = append(providers, "microsoft")
	}

	if config.GoogleOAuth.ClientSecret != "" {
		providers = append(providers, "google")
	}

	if config.GithubOAuth.ClientSecret != "" {
		providers = append(providers, "github")
	}

	return providers
}
