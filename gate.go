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

func (g Gate) CountModule(domain string) map[string]int {
	roles := g.GetRoles(domain)
	counter := make(map[string]int)
	moduleRole := make(map[string][]string)
	for _, role := range roles {
		modules := g.GetModuleRelatedByRole(domain, role)
		moduleRole[role] = modules
	}
	users := g.GetAllUsersRole(domain)
	for _, user := range users {
		for _, module := range moduleRole[user.Role] {
			counter[module]++
		}
	}
	return counter
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

func (g Gate) GetModuleRelatedByRole(domain, role string) []string {
	var modules []string
	mapModules := map[string]struct{}{}
	policies := g.E.GetFilteredPolicy(0, role, domain, "", "")
	for _, policy := range policies {
		moduleName := policy[2]
		if _, ok := mapModules[moduleName]; !ok {
			mapModules[moduleName] = struct{}{}
			modules = append(modules, moduleName)
		}
	}
	return modules
}
