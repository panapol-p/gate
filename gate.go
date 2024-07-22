package gate

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

type Gate struct {
	E *casbin.Enforcer
}

type UserRole struct {
	User string
	Role string
}

func NewGate(policyAdapter interface{}) (*Gate, error) {
	m := model.NewModel()
	m.AddDef("r", "r", "user, dom, module, action")
	m.AddDef("p", "p", "role, dom, module , action")
	m.AddDef("g", "g", " _, _, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", `g(r.user, p.role, r.dom) && r.dom == p.dom && r.module == p.module && (r.action == p.action || p.action == "*")`)

	e, err := casbin.NewEnforcer(m, policyAdapter)
	if err != nil {
		return nil, err
	}
	e.EnableAutoSave(true)
	return &Gate{E: e}, nil
}

func (g Gate) HasPermission(domain, user, module, action string) (bool, error) {
	//gate for admin
	isAdmin, err := g.IsAdmin(domain, user)
	if err != nil {
		return false, err
	}
	if isAdmin {
		return true, nil
	}

	//gate for non-admin
	res, err := g.E.Enforce(user, domain, module, action)
	return res, err
}

func (g Gate) IsAdmin(domain, user string) (bool, error) {
	f, err := g.E.GetFilteredGroupingPolicy(0, user, "admin", domain, "")
	if err != nil {
		return false, err
	}
	if len(f) > 0 {
		return true, nil
	}
	return false, nil
}

func (g Gate) GetRoles(domain string) ([]string, error) {
	rs, err := g.E.GetFilteredPolicy(0, "", domain, "")
	if err != nil {
		return make([]string, 0), err
	}
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
	return r, nil
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

func (g Gate) GetAllUsersRole(domain string) ([]UserRole, error) {
	var urs []UserRole
	users, err := g.E.GetFilteredGroupingPolicy(0, "", "", domain)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		ur := UserRole{
			User: user[0],
			Role: user[1],
		}
		urs = append(urs, ur)
	}
	return urs, nil
}

func (g Gate) GetUserRole(domain, user string) ([]string, error) {
	var roleUser []string
	roles, err := g.E.GetFilteredGroupingPolicy(0, user, "", domain)
	if err != nil {
		return []string{}, err
	}
	for _, role := range roles {
		roleUser = append(roleUser, role[1])
	}
	return roleUser, nil
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

func (g Gate) CountModule(domain string) (map[string]int, error) {
	roles, err := g.GetRoles(domain)
	if err != nil {
		return nil, err
	}
	counter := make(map[string]int)
	moduleRole := make(map[string][]string)
	for _, role := range roles {
		modules, err := g.GetModuleRelatedByRole(domain, role)
		if err != nil {
			return nil, err
		}
		moduleRole[role] = modules
	}
	users, err := g.GetAllUsersRole(domain)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		for _, module := range moduleRole[user.Role] {
			counter[module]++
		}
	}
	return counter, nil
}

func (g Gate) RevokeRoleToUser(domain, role, user string) error {
	_, err := g.E.RemoveGroupingPolicy(user, role, domain)
	return err
}

func (g Gate) Load() error {
	return g.E.LoadPolicy()
}

func (g Gate) Save() error {
	return g.E.SavePolicy()
}

func (g Gate) GetModuleRelatedByRole(domain, role string) ([]string, error) {
	var modules []string
	mapModules := map[string]struct{}{}
	policies, err := g.E.GetFilteredPolicy(0, role, domain, "", "")
	if err != nil {
		return []string{}, err
	}
	for _, policy := range policies {
		moduleName := policy[2]
		if _, ok := mapModules[moduleName]; !ok {
			mapModules[moduleName] = struct{}{}
			modules = append(modules, moduleName)
		}
	}
	return modules, nil
}
