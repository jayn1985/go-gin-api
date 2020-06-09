package auth

import (
	"github.com/gin-gonic/gin"
	"go-gin-api/app/controller/param_bind"
	"go-gin-api/app/route/middleware/sign/jwt"
	"go-gin-api/app/util/bind"
	"go-gin-api/app/util/response"
	"gopkg.in/go-playground/validator.v9"
)

func Login(c *gin.Context) {
	utilGin := response.Gin{Ctx: c}

	s, err := bind.Bind(&param_bind.AuthLogin{}, c)
	if err != nil {
		utilGin.Response(-1, err.Error(), nil)
		return
	}

	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		utilGin.Response(-1, err.Error(), nil)
		return
	}

	// query db
	account := s.(*param_bind.AuthLogin)
	if account.Username != "admin" || account.Password != "123456" {
		utilGin.Response(-1, "account error", nil)
		return
	}

	userId, userName := int64(1), "Jayn Yang"
	token, err := sign_jwt.CreateToken(&sign_jwt.UserSession{ID: userId, Name: userName})
	if err != nil {
		utilGin.Response(-1, err.Error(), nil)
		return
	}

	utilGin.Response(1, "success", token)
}
