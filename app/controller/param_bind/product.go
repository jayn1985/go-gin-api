package param_bind

type ProductAdd struct {
	Name string `form:"name" json:"name" validate:"required,NameValid"`
}

type AuthLogin struct {
	Username string `form:"username" json:"username" validate:"required"`
	Password string `form:"password" json:"password" validate:"required"`
}
