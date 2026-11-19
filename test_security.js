/**
 * Automated Security & Functionality Verification Suite
 * Tests all 7 security criteria without modifying production database.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');

// Use a temporary test database so production data is untouched
const TEST_DB_FILE = path.join(__dirname, 'data', 'test_security_db.json');
process.env.PORT = '3099';
process.env.SESSION_SECRET = 'test_secret_for_security_verification_key';
process.env.ALLOWED_ORIGINS = 'http://localhost:3099,http://127.0.0.1:3099,https://trusted-app.com';

// Mock DB_FILE for isolated testing
const initialTestDB = {
  users: [
    {
      id: 'usr_legacy_user',
      name: 'Legacy User',
      email: 'legacy@example.com',
      salt: '11223344556677889900aabbccddeeff',
      passwordHash: crypto.pbkdf2Sync('legacyPass123', '11223344556677889900aabbccddeeff', 1000, 32, 'sha256').toString('hex'),
      iterations: 1000, // Legacy iteration count
      createdAt: Date.now() - 86400000,
      settings: { defaultRingtone: 'chime', enableSound: true, enableNotifications: true }
    }
  ],
  sessions: {},
  tasks: [],
  history: []
};

fs.writeFileSync(TEST_DB_FILE, JSON.stringify(initialTestDB, null, 2), 'utf8');

// Load server by overriding DB_FILE
const serverPath = path.join(__dirname, 'server.js');
let serverCode = fs.readFileSync(serverPath, 'utf8');

// Replace DB_FILE target for the test runner instance
serverCode = serverCode.replace(
  "const DB_FILE = path.join(__dirname, 'data', 'database.json');",
  `const DB_FILE = ${JSON.stringify(TEST_DB_FILE)};`
);

// Write temporary test server
const TEST_SERVER_FILE = path.join(__dirname, 'test_server_runner.js');
fs.writeFileSync(TEST_SERVER_FILE, serverCode, 'utf8');

const { spawn } = require('child_process');
const nodeBin = process.execPath;

let serverProcess = null;
let testPassed = 0;
let testFailed = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    testPassed++;
  } else {
    console.error(`  [FAIL] ${testName}`);
    testFailed++;
  }
}

function request(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, headers: res.headers, body: json });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body: data });
        }
      });
    });
    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runTests() {
  console.log('\n======================================================');
  console.log('🔒 Starting Security & Functionality Verification Suite');
  console.log('======================================================\n');

  // Start the test server on port 3099
  serverProcess = spawn(nodeBin, [TEST_SERVER_FILE], {
    env: {
      ...process.env,
      PORT: '3099',
      SESSION_SECRET: 'test_secret_for_security_verification_key',
      ALLOWED_ORIGINS: 'http://localhost:3099,http://127.0.0.1:3099,https://trusted-app.com',
      PBKDF2_ITERATIONS: '600000'
    }
  });

  // Give server 1.5 seconds to bind
  await new Promise(r => setTimeout(r, 1500));

  try {
    // ----------------------------------------------------
    // TEST GROUP 1: PASSWORD SECURITY & REGISTRATION
    // ----------------------------------------------------
    console.log('--- 1. PASSWORD SECURITY & INPUT VALIDATION ---');

    // 1.1 Rejection of password < 8 characters
    const resShortPass = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { name: 'Shorty', email: 'short@example.com', password: '123' });
    assert(resShortPass.status === 400 && resShortPass.body.error.includes('8'), 'Registration rejects password with fewer than 8 characters');

    // 1.2 Rejection of invalid email
    const resBadEmail = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { name: 'Bad Email', email: 'invalid-email-format', password: 'ValidPassword123!' });
    assert(resBadEmail.status === 400 && resBadEmail.body.error.includes('email'), 'Registration rejects invalid email format');

    // 1.3 Successful registration of User A
    const resRegUserA = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { name: 'Alice Walker', email: 'alice@example.com', password: 'AlicePassword888!' });
    assert(resRegUserA.status === 201 && resRegUserA.body.token, 'Registration succeeds with valid email & 8+ char password');
    const tokenUserA = resRegUserA.body.token;

    // Verify 600,000 iterations in database
    const dbAfterReg = JSON.parse(fs.readFileSync(TEST_DB_FILE, 'utf8'));
    const aliceInDB = dbAfterReg.users.find(u => u.email === 'alice@example.com');
    assert(aliceInDB && aliceInDB.iterations === 600000, 'New registered user uses 600,000 PBKDF2 iterations');

    // 1.4 Token stored as hash in database (Zero plaintext session tokens)
    const rawTokenFoundInDB = Object.keys(dbAfterReg.sessions).includes(tokenUserA);
    assert(!rawTokenFoundInDB, 'Session tokens are stored as cryptographic hashes (raw token NOT in DB keys)');

    // ----------------------------------------------------
    // TEST GROUP 2: BACKWARD COMPATIBILITY & HASH MIGRATION
    // ----------------------------------------------------
    console.log('\n--- 2. BACKWARD COMPATIBILITY & LEGACY HASH MIGRATION ---');

    // Verify legacy user starts with 1,000 iterations in DB
    const dbBeforeMigration = JSON.parse(fs.readFileSync(TEST_DB_FILE, 'utf8'));
    const legacyBefore = dbBeforeMigration.users.find(u => u.email === 'legacy@example.com');
    assert(legacyBefore && legacyBefore.iterations === 1000, 'Legacy user initially has 1,000 iterations in database');

    // Login with legacy user
    const resLegacyLogin = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'legacy@example.com', password: 'legacyPass123' });
    assert(resLegacyLogin.status === 200 && resLegacyLogin.body.token, 'Legacy user logs in successfully without password reset');

    // Verify automatic hash migration to 600,000 iterations
    const dbAfterMigration = JSON.parse(fs.readFileSync(TEST_DB_FILE, 'utf8'));
    const legacyAfter = dbAfterMigration.users.find(u => u.email === 'legacy@example.com');
    assert(legacyAfter && legacyAfter.iterations === 600000 && legacyAfter.salt !== legacyBefore.salt,
      'Legacy password hash automatically upgraded to 600,000 iterations and fresh salt');

    // ----------------------------------------------------
    // TEST GROUP 3: DEMO ACCOUNT FUNCTIONALITY & ISOLATION
    // ----------------------------------------------------
    console.log('\n--- 3. DEMO ACCOUNT & WORKSPACE ISOLATION ---');

    // 3.1 Demo visitor 1 logs in via Quick Demo Sign In
    const resDemo1 = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'demo@remindme.com', password: 'password123' });
    assert(resDemo1.status === 200 && resDemo1.body.user.isDemo === true, 'Quick Demo Sign In succeeds and marks isDemo: true');
    const tokenDemo1 = resDemo1.body.token;
    const userDemo1Id = resDemo1.body.user.id;

    // 3.2 Demo visitor 2 logs in
    const resDemo2 = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'demo@remindme.com', password: 'password123' });
    assert(resDemo2.status === 200 && resDemo2.body.user.isDemo === true, 'Second Demo visitor logs in successfully');
    const tokenDemo2 = resDemo2.body.token;
    const userDemo2Id = resDemo2.body.user.id;

    // 3.3 Verify isolated IDs for demo visitors
    assert(userDemo1Id !== userDemo2Id, 'Demo visitors receive unique, isolated workspace IDs (No cross-visitor sharing)');

    // 3.4 Demo Visitor 1 creates a task
    const resTaskDemo1 = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/tasks',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenDemo1}`
      }
    }, { name: 'Demo 1 Secret Task', date: '2026-11-20', startTime: '10:00', endTime: '11:00', ringtone: 'chime', tagId: 'work' });
    assert(resTaskDemo1.status === 201, 'Demo visitor 1 creates task in their workspace');

    // 3.5 Demo Visitor 2 queries tasks - must NOT see Demo Visitor 1's task
    const resTasksDemo2 = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/tasks',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenDemo2}` }
    });
    const demo2Tasks = resTasksDemo2.body.tasks || [];
    assert(demo2Tasks.length === 0, 'Demo visitor 2 CANNOT see Demo visitor 1 tasks (Workspace Isolation Verified)');

    // ----------------------------------------------------
    // TEST GROUP 4: CROSS-USER DATA ISOLATION (REGISTERED)
    // ----------------------------------------------------
    console.log('\n--- 4. CROSS-USER TENANT DATA ISOLATION ---');

    // Register User B
    const resRegUserB = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { name: 'Bob Dylan', email: 'bob@example.com', password: 'BobPassword999!' });
    const tokenUserB = resRegUserB.body.token;

    // Alice creates a private task
    const resAliceTask = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/tasks',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenUserA}`
      }
    }, { name: 'Alice Confidential Medical Visit', date: '2026-11-20', startTime: '14:00', endTime: '15:00', ringtone: 'zen', tagId: 'health' });
    const aliceTaskId = resAliceTask.body.task.id;

    // Bob attempts to query Alice's task list
    const resBobTasks = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/tasks',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenUserB}` }
    });
    const bobCanSeeAliceTask = (resBobTasks.body.tasks || []).some(t => t.id === aliceTaskId);
    assert(!bobCanSeeAliceTask, 'Bob cannot see Alice private tasks via GET /api/tasks');

    // Bob attempts to modify Alice's task via PUT
    const resBobEditAlice = await request({
      hostname: 'localhost',
      port: 3099,
      path: `/api/tasks/${aliceTaskId}`,
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenUserB}`
      }
    }, { name: 'Hacked by Bob', completed: true });
    assert(resBobEditAlice.status === 404, 'Bob cannot edit Alice task (returns 404 Not Found for unauthorized user)');

    // Bob attempts to delete Alice's task via DELETE
    await request({
      hostname: 'localhost',
      port: 3099,
      path: `/api/tasks/${aliceTaskId}`,
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${tokenUserB}` }
    });

    // Check Alice's task still exists
    const resAliceCheck = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/tasks',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenUserA}` }
    });
    const aliceTaskStillExists = (resAliceCheck.body.tasks || []).some(t => t.id === aliceTaskId);
    assert(aliceTaskStillExists, 'Bob cannot delete Alice task (Deletion protected by user ownership check)');

    // Demo user attempts to access Alice's task
    const resDemoViewAlice = await request({
      hostname: 'localhost',
      port: 3099,
      path: `/api/tasks/${aliceTaskId}`,
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenDemo1}`
      }
    }, { name: 'Hacked by Demo' });
    assert(resDemoViewAlice.status === 404, 'Demo visitor cannot modify registered user task');

    // ----------------------------------------------------
    // TEST GROUP 5: TASK LIFECYCLE & HISTORY FUNCTIONALITY
    // ----------------------------------------------------
    console.log('\n--- 5. TASK LIFECYCLE & HISTORY FUNCTIONALITY ---');

    // Complete Alice's task
    const resComplete = await request({
      hostname: 'localhost',
      port: 3099,
      path: `/api/tasks/${aliceTaskId}`,
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenUserA}`
      }
    }, { completed: true });
    assert(resComplete.status === 200 && resComplete.body.task.completed === true, 'Task ticked as completed successfully');

    // Check Alice's history records
    const resHistory = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/history',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenUserA}` }
    });
    const hasHistoryRecord = (resHistory.body.records || []).some(r => r.taskId === aliceTaskId);
    assert(hasHistoryRecord && resHistory.body.stats.totalCompleted >= 1, 'History logs completion record and updates stats accurately');

    // ----------------------------------------------------
    // TEST GROUP 6: CORS & SECURITY HEADERS
    // ----------------------------------------------------
    console.log('\n--- 6. CORS & HTTP SECURITY HEADERS ---');

    // Authorized origin gets Access-Control-Allow-Origin
    const resTrustedOrigin = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/me',
      method: 'GET',
      headers: {
        'Origin': 'https://trusted-app.com',
        'Authorization': `Bearer ${tokenUserA}`
      }
    });
    assert(resTrustedOrigin.headers['access-control-allow-origin'] === 'https://trusted-app.com',
      'Whitelisted Origin receives Access-Control-Allow-Origin: https://trusted-app.com');

    // Untrusted origin does NOT receive Access-Control-Allow-Origin
    const resUntrustedOrigin = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/me',
      method: 'GET',
      headers: {
        'Origin': 'https://malicious-attacker.com',
        'Authorization': `Bearer ${tokenUserA}`
      }
    });
    assert(!resUntrustedOrigin.headers['access-control-allow-origin'],
      'Untrusted Origin does NOT receive Access-Control-Allow-Origin header (Wildcard removed)');

    // Security headers present
    assert(resTrustedOrigin.headers['x-content-type-options'] === 'nosniff' &&
           resTrustedOrigin.headers['x-frame-options'] === 'DENY',
           'Security headers X-Content-Type-Options: nosniff and X-Frame-Options: DENY are present');

    // ----------------------------------------------------
    // TEST GROUP 7: SESSION EXPIRATION & LOGOUT
    // ----------------------------------------------------
    console.log('\n--- 7. SESSION EXPIRATION & LOGOUT ---');

    // Logout User A
    const resLogout = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/logout',
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenUserA}` }
    });
    assert(resLogout.status === 200, 'Logout succeeds');

    // Token no longer valid after logout
    const resAfterLogout = await request({
      hostname: 'localhost',
      port: 3099,
      path: '/api/auth/me',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenUserA}` }
    });
    assert(resAfterLogout.status === 401, 'Logged out token is immediately rejected with 401 Unauthorized');

  } catch (err) {
    console.error('Test execution error:', err);
    testFailed++;
  } finally {
    if (serverProcess) {
      serverProcess.kill('SIGKILL');
    }

    // Clean up temporary test files
    try {
      if (fs.existsSync(TEST_DB_FILE)) fs.unlinkSync(TEST_DB_FILE);
      if (fs.existsSync(TEST_SERVER_FILE)) fs.unlinkSync(TEST_SERVER_FILE);
    } catch {}

    console.log('\n======================================================');
    console.log(`Test Results: ${testPassed} Passed, ${testFailed} Failed`);
    console.log('======================================================\n');

    process.exit(testFailed === 0 ? 0 : 1);
  }
}

runTests();
