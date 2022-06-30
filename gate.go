package gate

import (
	"github.com/casbin/casbin/v2"
)

type Gate struct {
	E *casbin.Enforcer
}

type UserRole struct {
	User string
	Role string
}

func NewGate(model, policyAdapter interface{}) (*Gate, error) {
	e, err := casbin.NewEnforcer(model, policyAdapter)
	if err != nil {
		return nil, err
	}
	e.EnableAutoSave(true)
	return &Gate{E: e}, nil
}

func (g Gate) HasPermission(domain, user, module, action string) (bool, error) {
	//gate for admin
	if g.IsAdmin(domain, user) {
		return true, nil
	}

	//gate for non-admin
	res, err := g.E.Enforce(user, domain, module, action)
	return res, err
}

func (g Gate) IsAdmin(domain, user string) bool {
	f := g.E.GetFilteredGroupingPolicy(0, user, "admin", domain, "")
	if len(f) > 0 {
		return true
	}
	return false
}

func (g Gate) GetRoles(domain string) []string {
	rs := g.E.GetFilteredPolicy(0, "", domain, "")
	var r []string
	mapRoles := map[string]struct{}{}

	//add admin role by default
	r = append(r, "admin")
	for i := range rs {
		roleNames := rs[i][0]
		if _, ok := mapRoles[roleNames]; !ok {
			mapRoles[roleNames] = struct{}{}
			r = append(r, roleNames)
		}
	}
	return r
}

func (g Gate) GetPermissionsForRole(domain string, role string) []string {
	if role == "admin" {
		return []string{"*"}
	}

	ps := g.E.GetPermissionsForUserInDomain(role, domain)
	var p []string
	for i := range ps {
		p = append(p, ps[i][2]+"."+ps[i][3])
	}
	return p
}

func (g Gate) GetAllUsersRole(domain string) []UserRole {
	var urs []UserRole
	users := g.E.GetFilteredGroupingPolicy(0, "", "", domain)
	for _, user := range users {
		ur := UserRole{
			User: user[0],
			Role: user[1],
		}
		urs = append(urs, ur)
	}
	return urs
}

func (g Gate) AssignPermissionToRole(domain, role, module, action string) error {
	_, err := g.E.AddPolicy(role, domain, module, action)
	return err
}

func (g Gate) RevokerPermissionToRole(domain, role, module, action string) error {
	_, err := g.E.RemovePolicy(role, domain, module, action)
	return err
}

func (g Gate) AssignRoleToUser(domain, role, user string) error {
	_, err := g.E.AddGroupingPolicy(user, role, domain)
	return err
}

func (g Gate) RevokeRoleToUser(domain, role, user string) error {
	_, err := g.E.RemoveGroupingPolicy(user, role, domain)
	return err
}

func (g Gate) Save() error {
	return g.E.SavePolicy()
}
