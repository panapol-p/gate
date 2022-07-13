# gate
[![tests](https://github.com/panapol-p/gate/actions/workflows/ci.yml/badge.svg)](https://github.com/panapol-p/gate/actions/workflows/ci.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=PP-Gate&metric=coverage)](https://sonarcloud.io/summary/new_code?id=PP-Gate) 
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=PP-Gate&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=PP-Gate)
[![Go Reference](https://pkg.go.dev/badge/github.com/panapol-p/gate.svg)](https://pkg.go.dev/github.com/panapol-p/gate)

role-based access control (RBAC) for multi domain/tenant implementation in Golang (casbin wrapper)
<hr>

## About <a id="about"></a>
*gate* is go package for RBAC with multi tenant/domain, this one is implement base on [casbin](https://github.com/casbin/casbin), some feature that useful for multi domain was added.

#### word that you need to know
- casbin model use to set casbin policy pattern (gate fix this one for easy to use)
- casbin policy use to store policy rule in casbin adapter (ex. domain has user and role and role in domain has permission) you can see example below
<br>
```casbincsv
//permission is contain module name and action name
//policy type p -> role writer in domain1 has write permission in module data1
p, writer, domain1, data1, write

//policy type p -> role visitor3 in domain3 has all permission in module data3
p, visitor3, domain3, data3, *

//policy type g -> alice is admin role in domain1 (notice : admin role has all permission in this domain)
g, alice, admin, domain1

//policy type g -> alice is visitor3 role in domain3
g, alice, visitor3, domain3
```
  
<br><br>
if you need  more information please follow the casbin document [casbin document](https://casbin.org/docs/en/supported-models)

## Features
- [x] support single domain and multi domain
- [x] assign , revoke permission to role
- [x] assign , revoke role to user
- [x] check permission
- [x] check admin role
- [x] list all role
- [x] list all permission in role
- [x] list all user with role
- [x] count module usage in domain (some application need to know module usage for limitation)
- [ ] assign role to user with module usage license limitation in domain (coming soon)
- [x] auto update when package dependency is update (we use [dependabot](https://github.com/dependabot/dependabot-core) to auto pull request for new package version)

## Install <a id="install"></a>
```sh
go get -u github.com/panapol-p/gate
```

## Example <a id="example"></a>

#### To create new gate
you can use another adapter to store casbin policy (mongo,postgresql,mysql,aws s3 or etc.) by follow casbin adapter [casbin adapter](https://casbin.org/docs/en/adapters)<br>
<b>notice</b> : some adapter is not support `auto-save` when you update policy or rule you must save and load policy by using `g.Load()` or `g.Save()`<br>
<b>notice2</b> : if you need to use some feature from native casbin you can called by using `g.E` this one is [natice casbin enforcer](https://github.com/casbin/casbin/blob/master/enforcer.go)<br>
<b>notice3</b> : if you build aplication that support scalable mode , please don't forget to set [casbin watcher](https://casbin.org/docs/en/watchers) to trigger event when some node has policy update, another node will know and use `g.Load()` for update policy each node otherwise all of your node will be not use same policy rules
```go
func main(){
	//set adapter
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
	//create new gate
    g, err := NewGate(a)
}
```

#### To assing permission to role and assign role to use `(ex. usecase -> manage user role and permission in user management)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)
	// assign permission:write for module:resource1 to role:dep1 in domain:domain5
    err = g.AssignPermissionToRole("domain5", "dep1", "resource1", "write")
    // assign role:dep1 to user:bella in domain:domain5
    err = g.AssignRoleToUser("domain5", "dep1", "bella")
}
```

#### To revoke permission to role and revoke role to user `(ex. usecase -> manage user role and permission in user management)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)
	// revoke permission:write for module:resource1 to role:dep1 in domain:domain5
    err = g.RevokerPermissionToRole("domain5", "dep1", "resource1", "write")
    // revoke role:dep1 to user:bella in domain:domain5
    err = g.RevokeRoleToUser("domain5", "dep1", "bella")
}
```

#### To check user has permission in this domain or not `(ex. usecase -> middleware for http request)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)

	//user:bella has permission:write for module:resource1 in domain:domain5 or not?
    h, err = g.HasPermission("domain5", "bella", "resource1", "write")
    //output : true / false
}
```

#### To check user is admin role in this domain or not `(ex. usecase -> middleware for admin http request)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)

	//user:alice is role:admin in domain:domain1 or not?
    isAdmin := g.IsAdmin("domain1", "alice")
	//output : true / false
}
```

#### To list all role in this domain `(ex. usecase -> show all role in user management page)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)

	//list all role in domain:domain1
    r1 := g.GetRoles("domain1")
	//output : domain1 has role:admin , writer , reader , visitor
    //output : []string{"admin", "writer", "reader", "visitor"}
}
```

#### To list all user with role in this domain `(ex. usecase -> show all user with role in user management page)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)

	//list all user with role in domain:domain1
    u := g.GetAllUsersRole("domain1")
	//output : domain1 has user:alice with role:admin and user:bob with role:reader
	//output []UserRole{ {"alice", "admin"}, {"bob", "reader"}}
}
```

#### To list all permission for role in this domain `(ex. usecase -> manage permission in role in user management page)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)

	//list all permission for role:writer in domain:domain1
	//notice : if you use admin it will be return all permission in this domain
    p := g.GetPermissionsForRole("domain1", "writer")
    //output : combine module and permission(action) with dot
	//output : role:wrtiter in domain1 has read and write in module:data1
    //output : []string{"data1.read", "data1.write"}
}
```


#### To count module usage in this domain `(ex. usecase -> some application need to count the number of module usage)`
```go
func main(){
    a := fileadapter.NewAdapter("./testdata/rbac_with_domains_policy.csv")
    g, err := NewGate(a)

	//list all module with number of usage in domain:domain1
    m := g.CountModule("domain1")
	//output : domain1 use module:data2 1 license and use module:data3 2 licenses
	//output : map[string]int{ "data2": 1, "data3": 2}
}
```

#### To assign role to user with  module usage limitation `(ex. usecase -> some application need to limit the number of module usage)`
coming soon

## License <a id="license"></a>
Distributed under the MIT License. See [license](LICENSE) for more information.

## Contributing <a id="contributing"></a>
Contributions are welcome! Feel free to check our [open issues](https://github.com/panapol-p/gate/issues).