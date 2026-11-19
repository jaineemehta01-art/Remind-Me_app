# ≡ƒöö Remind Me - Task & Reminder App with Full Backend & User History

A modern, responsive, and aesthetic task reminder application built in **React** and backed by a **Node.js REST API server**. Designed to help users remember daily tasks, meetings, events, and to-dos so nothing gets forgotten, while securely tracking their accomplishment records and history over time.

---

## ≡ƒîƒ New Features: Backend, Login & Records History

### 1. ≡ƒöÉ User Authentication (Backend & Frontend)
* **User Accounts:**
  * **Sign In:** Secure login with email and password.
  * **Register:** Create new accounts with name, email, and password.
  * **1-Click Demo Login:** Log in instantly with demo account (`demo@remindme.com` / `password123`).
  * **Guest Mode:** Use the app immediately without logging in; data syncs seamlessly when an account is connected.
* **Security:**
  * Passwords cryptographically hashed using Node.js native `crypto.pbkdf2Sync` with per-user unique salt.
  * Token-based session management.
* **Persistent Storage:**
  * Persistent JSON database located at `data/database.json`.
  * Preserves user accounts, tasks, and completion history across restarts.

### 2. ≡ƒôè User Records & History Dashboard ("Tasks completed")
* **Lifetime Completion Metrics:**
  * Total tasks remembered and completed.
  * Accuracy rate percentage.
  * Current daily streak counter (`≡ƒöÑ Day Streak`).
  * Count of tasks completed today.
* **Completion Archive:**
  * Chronologically grouped history of all remembered tasks.
  * Includes completion timestamp, duration, and category tags.
  * Export tasks to device calendar via **`≡ƒôÑ Export .ICS`**.

---

## ≡ƒûÑ∩╕Å The 3 Primary Screens & Screen Flow

### Screen 1: Main Screen ("Home")
* **"Remind me" Branding** with live system clock status.
* **Linked Device Clock & Calendar:**
  * Digital clock live counter updated every second.
  * Date selector with day-by-day navigation.
* **"What's upcoming":**
  * Lists upcoming tasks with **Start time**, **End time**, and category tag in its **pastel color**.
  * Shows selected ringtone with instant preview.
  * **Tick Box:** Ticking the empty box plays a celebratory chime, triggers a confetti burst, and displays the required popup:
    > **"Congratulations, you remembered your task"**
* **Upcoming Task Alarm:**
  * Fires automatically when the device clock matches the task's start time.
  * Modal with **"Γ£ô I Remembered! (Done)"**, **"≡ƒÆñ Snooze 5 Min"**, and **"Dismiss"**.
  * Includes a **"ΓÅ░ Test Alarm"** simulator button.

### Screen 2: "Create New Task" Screen
Features the **6 primary controls/buttons**:
1. **Button 1: "Task Name"** ΓÇö Text input with quick suggestions.
2. **Button 2: "Date"** ΓÇö Date picker linked with device calendar.
3. **Button 3: "Start time"** ΓÇö Time when reminder alarm sounds.
4. **Button 4: "End time"** ΓÇö Time when task concludes / reminders stop.
5. **Button 5: "Remind Me"** ΓÇö Ringtone selector with **6 synthesized ringtones** (*Gentle Chime*, *Digital Alarm*, *Marimba Melody*, *Zen Gong*, *Morning Harp*, *Classic Beep*) and audio previews.
6. **Button 6: "Type of task"** ΓÇö 8 pastel category tags (*Work*, *Meeting*, *Personal*, *Health*, *Study*, *Shopping*, *Finance*, *Urgent*).

### Screen 3: Result Screen ("End of Day Celebration")
* **Huge Animated Tick Mark Sign:** Custom SVG checkmark with animated circle and stroke expansion.
* **Motivational Quote Card:** Inspiring productivity quote with quote shuffler.
* **Accomplishment Metrics:** 100% completion rate badge.
* **"Back to home" Button:** Primary button at the end redirecting back to Screen 1.

### 4 Bottom Navigation Buttons
1. **Home** ΓÇö Main screen with "Remind me" and "What's upcoming".
2. **Calendar** ΓÇö Device calendar view with **≡ƒôÑ Export .ICS** download.
3. **Tasks completed** ΓÇö History & Records dashboard.
4. **User settings** ΓÇö Audio alarm toggles, ringtone test, and account profile.

---

## ≡ƒÜÇ How to Run the Application

### Option A: One-Click Windows Launcher (Recommended)
Simply double-click:
```
run_app.bat
```
This script automatically:
1. Detects your Node.js runtime.
2. Launches the backend server (`server.js`) on `http://localhost:3000`.
3. Opens your default web browser directly to `http://localhost:3000`.

### Option B: Terminal / Command Line
```powershell
cd "c:\Users\Chethan\Downloads\Remind Me_app"
node server.js
```
Then visit `http://localhost:3000` in any browser.

---

## ≡ƒöÉ Pre-Seeded Demo Account
For testing with preloaded tasks and history, use:
* **Email:** `demo@remindme.com`
* **Password:** `password123`
*(Or click the **"ΓÜí Quick Demo Sign In"** button on the sign-in modal)*

---

## ≡ƒôü File Structure
```
Remind Me_app/
Γö£ΓöÇΓöÇ index.html       # Single-Page Frontend (100% self-contained & offline-ready)
Γö£ΓöÇΓöÇ server.js        # Node.js REST API Backend Server (Auth, Tasks, History)
Γö£ΓöÇΓöÇ run_app.bat      # One-click Windows launcher
Γö£ΓöÇΓöÇ package.json     # Project metadata
Γö£ΓöÇΓöÇ README.md        # Documentation
Γö£ΓöÇΓöÇ data/
Γöé   ΓööΓöÇΓöÇ database.json # Persistent JSON Database (Users, Tasks, History)
ΓööΓöÇΓöÇ vendor/
    Γö£ΓöÇΓöÇ preact.umd.js
    Γö£ΓöÇΓöÇ hooks.umd.js
    ΓööΓöÇΓöÇ compat.umd.js
```