package gate

import (
	"testing"

	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/stretchr/testify/assert"
)

func TestNewGate(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)
	assert.NotNil(t, g)

	g, err = NewGate("./no_file")
	assert.Error(t, err)
	assert.Nil(t, g)
}

func TestGate_GetAllUsersRole(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	u1, err := g.GetAllUsersRole("domain1")
	expectedD1 := []UserRole{
		{"alice", "admin"},
		{"bob", "reader"},
		{"foo", "visitor"},
		{"chalet", "visitor"},
	}
	assert.NoError(t, err)
	assert.Equal(t, expectedD1, u1)

	u2, err := g.GetAllUsersRole("domain2")
	expectedD2 := []UserRole{
		{"alice", "reader2"},
		{"bob", "admin"},
		{"foo", "visitor2"},
		{"chalet", "visitor2"},
	}
	assert.NoError(t, err)
	assert.Equal(t, expectedD2, u2)

	u3, err := g.GetAllUsersRole("domain3")
	expectedD3 := []UserRole{
		{"alice", "visitor3"},
		{"bob", "reader3"},
		{"chalet", "reader3"},
		{"foo", "admin"},
	}
	assert.NoError(t, err)
	assert.Equal(t, expectedD3, u3)

	u4, err := g.GetAllUsersRole("domain4")
	assert.NoError(t, err)
	assert.Nil(t, u4)
}

func TestGate_GetPermissionsForRole(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	ps := g.E.GetPermissionsForUserInDomain("writer", "domain1")
	var p []string
	for i := range ps {
		p = append(p, ps[i][2]+"."+ps[i][3])
	}

	// test admin role
	p11 := g.GetPermissionsForRole("domain1", "admin")
	assert.Equal(t, []string{"*"}, p11)
	p21 := g.GetPermissionsForRole("domain2", "admin")
	assert.Equal(t, []string{"*"}, p21)
	p31 := g.GetPermissionsForRole("domain3", "admin")
	assert.Equal(t, []string{"*"}, p31)

	//test domain1
	p12 := g.GetPermissionsForRole("domain1", "writer")
	assert.Equal(t, []string{"data1.read", "data1.write"}, p12)
	p13 := g.GetPermissionsForRole("domain1", "reader")
	assert.Equal(t, []string{"data2.read", "data2.download"}, p13)
	p14 := g.GetPermissionsForRole("domain1", "visitor")
	assert.Equal(t, []string{"data3.view"}, p14)

	//test domain2
	p22 := g.GetPermissionsForRole("domain2", "writer2")
	assert.Equal(t, []string{"data1.read", "data1.write", "data1.download"}, p22)
	p23 := g.GetPermissionsForRole("domain2", "reader2")
	assert.Equal(t, []string{"data2.view"}, p23)

	//test domain3
	p32 := g.GetPermissionsForRole("domain3", "writer3")
	assert.Equal(t, []string{"data1.write", "data2.download"}, p32)
	p33 := g.GetPermissionsForRole("domain3", "reader3")
	assert.Equal(t, []string{"data2.read"}, p33)
	p34 := g.GetPermissionsForRole("domain3", "visitor3")
	assert.Equal(t, []string{"data3.*"}, p34)
	p35 := g.GetPermissionsForRole("domain3", "Observer3")
	assert.Equal(t, []string{"data3.view"}, p35)

	//test no role in domain
	p15 := g.GetPermissionsForRole("domain1", "visitor3")
	assert.Nil(t, p15)
	p24 := g.GetPermissionsForRole("domain1", "visitor3")
	assert.Nil(t, p24)
	p36 := g.GetPermissionsForRole("domain1", "visitor3")
	assert.Nil(t, p36)

	//test no domain
	p41 := g.GetPermissionsForRole("domain4", "visitor")
	assert.Nil(t, p41)
}

func TestGate_GetRoles(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	r1, err := g.GetRoles("domain1")
	assert.NoError(t, err)
	assert.Equal(t, []string{"admin", "writer", "reader", "visitor"}, r1)

	r2, err := g.GetRoles("domain2")
	assert.NoError(t, err)
	assert.Equal(t, []string{"admin", "writer2", "reader2"}, r2)

	r3, err := g.GetRoles("domain3")
	assert.NoError(t, err)
	assert.Equal(t, []string{"admin", "writer3", "reader3", "visitor3", "Observer3"}, r3)
}

func TestGate_HasPermission(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	//domain1
	p11, err := g.HasPermission("domain1", "alice", "data1", "write")
	assert.NoError(t, err)
	assert.Equal(t, true, p11)
	p12, err := g.HasPermission("domain1", "alice", "data4", "write")
	assert.NoError(t, err)
	assert.Equal(t, true, p12)
	p13, err := g.HasPermission("domain1", "bob", "data2", "download")
	assert.NoError(t, err)
	assert.Equal(t, true, p13)
	p14, err := g.HasPermission("domain1", "bob", "data2", "write")
	assert.NoError(t, err)
	assert.Equal(t, false, p14)

	//domain2
	p21, err := g.HasPermission("domain2", "alice", "data2", "download")
	assert.NoError(t, err)
	assert.Equal(t, false, p21)
	p22, err := g.HasPermission("domain2", "alice", "data2", "view")
	assert.NoError(t, err)
	assert.Equal(t, true, p22)
	p23, err := g.HasPermission("domain2", "bob", "data2", "download")
	assert.NoError(t, err)
	assert.Equal(t, true, p23)
	p24, err := g.HasPermission("domain2", "bob", "data2", "view")
	assert.NoError(t, err)
	assert.Equal(t, true, p24)
	p25, err := g.HasPermission("domain2", "foo", "data2", "view")
	assert.NoError(t, err)
	assert.Equal(t, false, p25)

	//domain3
	p31, err := g.HasPermission("domain3", "foo", "data2", "view")
	assert.NoError(t, err)
	assert.Equal(t, true, p31)
	p32, err := g.HasPermission("domain3", "alice", "data3", "view")
	assert.NoError(t, err)
	assert.Equal(t, true, p32)
	p321, err := g.HasPermission("domain3", "alice", "data3", "write")
	assert.NoError(t, err)
	assert.Equal(t, true, p321)
	p33, err := g.HasPermission("domain3", "alice", "data2", "view")
	assert.NoError(t, err)
	assert.Equal(t, false, p33)
	p34, err := g.HasPermission("domain3", "bob", "data2", "view")
	assert.NoError(t, err)
	assert.Equal(t, false, p34)
	p35, err := g.HasPermission("domain3", "bob", "data2", "read")
	assert.NoError(t, err)
	assert.Equal(t, true, p35)

	//no user
	p41, err := g.HasPermission("domain1", "bunny", "data2", "read")
	assert.NoError(t, err)
	assert.Equal(t, false, p41)

	//no domain
	p51, err := g.HasPermission("domain4", "alice", "data2", "read")
	assert.NoError(t, err)
	assert.Equal(t, false, p51)
}

func TestGate_IsAdmin(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	//domain1
	isAdmin, err := g.IsAdmin("domain1", "alice")
	assert.NoError(t, err)
	assert.Equal(t, true, isAdmin)
	isAdmin, err = g.IsAdmin("domain1", "bob")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)

	//domain2
	isAdmin, err = g.IsAdmin("domain2", "alice")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)
	isAdmin, err = g.IsAdmin("domain2", "bob")
	assert.NoError(t, err)
	assert.Equal(t, true, isAdmin)

	//domain3
	isAdmin, err = g.IsAdmin("domain3", "alice")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)
	isAdmin, err = g.IsAdmin("domain3", "bob")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)
	isAdmin, err = g.IsAdmin("domain3", "foo")
	assert.NoError(t, err)
	assert.Equal(t, true, isAdmin)

	//no user
	isAdmin, err = g.IsAdmin("domain1", "bee")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)

	//no domain
	isAdmin, err = g.IsAdmin("domain4", "alice")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)
	isAdmin, err = g.IsAdmin("domain4", "bob")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)
	isAdmin, err = g.IsAdmin("domain4", "foo")
	assert.NoError(t, err)
	assert.Equal(t, false, isAdmin)
}

func TestGate_GetUsersRole(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	//domain1
	r, err := g.GetUserRole("domain1", "alice")
	assert.NoError(t, err)
	assert.Equal(t, []string{"admin"}, r)
	r, err = g.GetUserRole("domain1", "bob")
	assert.NoError(t, err)
	assert.Equal(t, []string{"reader"}, r)
	r, err = g.GetUserRole("domain1", "foo")
	assert.NoError(t, err)
	assert.Equal(t, []string{"visitor"}, r)
	r, err = g.GetUserRole("domain1", "chalet")
	assert.NoError(t, err)
	assert.Equal(t, []string{"visitor"}, r)

	//domain2
	r, err = g.GetUserRole("domain2", "alice")
	assert.NoError(t, err)
	assert.Equal(t, []string{"reader2"}, r)
	r, err = g.GetUserRole("domain2", "bob")
	assert.NoError(t, err)
	assert.Equal(t, []string{"admin"}, r)
	r, err = g.GetUserRole("domain2", "foo")
	assert.NoError(t, err)
	assert.Equal(t, []string{"visitor2"}, r)
	r, err = g.GetUserRole("domain2", "chalet")
	assert.NoError(t, err)
	assert.Equal(t, []string{"visitor2"}, r)

	//domain3
	r, err = g.GetUserRole("domain3", "foo")
	assert.NoError(t, err)
	assert.Equal(t, []string{"admin"}, r)
	r, err = g.GetUserRole("domain3", "alice")
	assert.NoError(t, err)
	assert.Equal(t, []string{"visitor3"}, r)
	r, err = g.GetUserRole("domain3", "bob")
	assert.NoError(t, err)
	assert.Equal(t, []string{"reader3"}, r)
	r, err = g.GetUserRole("domain3", "chalet")
	assert.NoError(t, err)
	assert.Equal(t, []string{"reader3"}, r)

	//no user
	r, err = g.GetUserRole("domain1", "bon")
	assert.NoError(t, err)
	assert.Nil(t, r)
	//no domain
	r, err = g.GetUserRole("domain4", "alice")
	assert.NoError(t, err)
	assert.Nil(t, r)
}

func TestGate_AddPolicy(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	h, err := g.HasPermission("domain5", "bella", "resource1", "write")
	assert.NoError(t, err)
	assert.Equal(t, false, h)

	err = g.AssignPermissionToRole("domain5", "dep1", "resource1", "write")
	assert.NoError(t, err)
	err = g.AssignRoleToUser("domain5", "dep1", "bella")
	assert.NoError(t, err)

	err = g.Save()
	assert.NoError(t, err)

	h, err = g.HasPermission("domain5", "bella", "resource1", "write")
	assert.NoError(t, err)
	assert.Equal(t, true, h)

	err = g.RevokeRoleToUser("domain5", "dep1", "bella")
	assert.NoError(t, err)
	h, err = g.HasPermission("domain5", "bella", "resource1", "write")
	assert.NoError(t, err)
	assert.Equal(t, false, h)

	err = g.RevokerPermissionToRole("domain5", "dep1", "resource1", "write")
	assert.NoError(t, err)
	h, err = g.HasPermission("domain5", "bella", "resource1", "write")
	assert.NoError(t, err)
	assert.Equal(t, false, h)

	err = g.Save()
	assert.NoError(t, err)

	err = g.Load()
	assert.NoError(t, err)
}

func TestGate_CountModule(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	c, err := g.CountModule("domain1")
	assert.NoError(t, err)
	expect := map[string]int{
		"data2": 1,
		"data3": 2,
	}
	assert.Equal(t, expect, c)

	c, err = g.CountModule("domain2")
	assert.NoError(t, err)
	expect = map[string]int{
		"data2": 1,
	}
	assert.Equal(t, expect, c)

	c, err = g.CountModule("domain3")
	assert.NoError(t, err)
	expect = map[string]int{
		"data2": 2,
		"data3": 1,
	}
	assert.Equal(t, expect, c)

	c, err = g.CountModule("domain5")
	assert.NoError(t, err)
	expect = map[string]int{}
	assert.Equal(t, expect, c)
}

func TestGate_GetModuleRelatedByRole(t *testing.T) {
	a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	g, err := NewGate(a)
	assert.NoError(t, err)

	m, err := g.GetModuleRelatedByRole("domain1", "reader")
	assert.NoError(t, err)
	expect := []string{"data2"}
	assert.Equal(t, expect, m)

	m, err = g.GetModuleRelatedByRole("domain1", "visitor")
	assert.NoError(t, err)
	expect = []string{"data3"}
	assert.Equal(t, expect, m)

	m, err = g.GetModuleRelatedByRole("domain1", "writer")
	assert.NoError(t, err)
	expect = []string{"data1"}
	assert.Equal(t, expect, m)

	m, err = g.GetModuleRelatedByRole("domain1", "writer2")
	assert.NoError(t, err)
	assert.Nil(t, m)

	m, err = g.GetModuleRelatedByRole("domain5", "writer2")
	assert.NoError(t, err)
	assert.Nil(t, m)
}
