// MongoDB seed data for NoSQL Injection Lab
// Fictional lab users only — no real data

db = db.getSiblingDB('lab_nosql');

db.users.drop();
db.users.insertMany([
  { username: "alice", password: "lab_alice_pass", role: "user", email: "alice@lab.local" },
  { username: "bob",   password: "lab_bob_pass",   role: "user", email: "bob@lab.local" },
  { username: "admin", password: "lab_admin_pass", role: "admin", email: "admin@lab.local" }
]);

print("NoSQL Lab: seed data loaded (" + db.users.countDocuments() + " users)");
