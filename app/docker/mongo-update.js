db.createCollection("roles");
db.createColleciton("LoginToken")

db.roles.insertMany([
  {
    _id: "R001",
    roleName: "ADMIN",
    description: "시스템 관리자 권한"
  },
  {
    _id: "R002",
    roleName: "USER",
    description: "일반 사용자 권한"
  },
  {
    _id: "R003",
    roleName: "GUEST",
    description: "비로그인 사용자 권한"
  }
]);
