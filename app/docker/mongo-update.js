db.createCollection("roles");
db.createColleciton("LoginToken")

db.roles.insertMany([
  {
    roles: "ADMIN",
    description: "시스템 관리자 권한"
  },
  {
    roles: "USER",
    description: "일반 사용자 권한"
  },
  {
    roles: "GUEST",
    description: "비로그인 사용자 권한"
  }
]);
