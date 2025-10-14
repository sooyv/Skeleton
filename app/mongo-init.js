// init-mongo.js
db = db.getSiblingDB("skeleton"); // skeleton DB 선택/생성

db.createUser({
    user: "skeleton_user",
    pwd: "qlqjs1212",
    roles: [
        { role: "readWrite", db: "skeleton" }
    ]
});

db.createCollection("user");
