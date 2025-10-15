db = db.getSiblingDB('admin');
db.system.users.update({"user":"init"}, {$set:{"user":"mongo_root"}})
db.changeUserPassword('mongo_root', 'mongoDkagh#2')

db = db.getSiblingDB("skeleton"); // skeleton DB 선택/생성

db.createUser({
    user: "skeleton_user",
    pwd: "qlqjs1212",
    roles: [
        { role: "readWrite", db: "skeleton" }
    ]
});

// log quiet
db.setLogLevel(0);
// install after retry...
disableTelemetry();

db.createCollection("user");
