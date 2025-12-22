# 🛡️ UrbanPulse Server | API Infrastructure

This is the robust Node.js/Express backend for **UrbanPulse**, providing secure data management, role-based access control, and seamless integration with Firebase Admin SDK and MongoDB.

---

### 🚀 Live API Base URL
- **Production:** [https://urban-pulse-server.vercel.app](https://urban-pulse-server.vercel.app)
- **Local:** `http://localhost:5000`

---

### 🛠️ Core Technologies



- **Node.js & Express.js:** Fast, unopinionated web framework.
- **MongoDB & Mongoose:** NoSQL database for flexible infrastructure reporting.
- **Firebase Admin SDK:** Server-side verification of Firebase ID Tokens.
- **Dotenv:** Secure management of environment variables.
- **CORS:** Configured for secure cross-origin resource sharing.

---

### 🔐 Security & Middleware

The server implements a custom `verifyFBToken` middleware to ensure only authenticated users can access protected routes.

1.  **Firebase ID Verification:** Validates the Google/Firebase token sent from the client.
2.  **Role Injection:** Automatically fetches the user's role (`admin`, `staff`, or `citizen`) from MongoDB and attaches it to the request object (`req.user_role`).
3.  **Ownership Check:** Prevents users from modifying data that does not belong to them.

---

### 🛣️ API Endpoints

#### 👤 Users & Auth
- `POST /users` - Save new user to DB on registration.
- `GET /users/:email` - Get specific user details and role.
- `PATCH /users/:email` - Update profile or change roles (Admin Only).

#### 🚧 Infrastructure Issues
- `GET /issues` - Fetch all issues (with pagination).
- `POST /issues` - Create a new infrastructure report.
- `PATCH /issue/:id/upvote` - Increment upvote count for an issue.
- `PATCH /issue/:id/status` - Update issue status (Staff/Admin Only).

#### 📊 Dashboard Stats
- `GET /admin-stats` - Aggregate data for the Admin overview.
- `GET /staff-stats/:email` - Performance and task tracking for staff members.

---

### 🖼️ Database Schema Overview



UrbanPulse uses a relational-like NoSQL structure:
- **Users Collection:** `{ email, displayName, photoURL, role, isBlocked }`
- **Issues Collection:** `{ title, category, photoUrl, district, upazila, status, upvotes, reporterEmail }`

---

### ⚙️ Local Setup

1.  **Clone the server repo:**
    ```bash
    git clone [https://github.com/the-abed/urban-pulse-server.git](https://github.com/the-abed/urban-pulse-server.git)
    ```
2.  **Install dependencies:**
    ```bash
    npm install
    ```
3.  **Environment Variables (`.env`):**
    ```env
    PORT=5000
    DB_USER=your_db_username
    DB_PASS=your_db_password
    # Firebase Service Account JSON keys here
    ```
4.  **Start the server:**
    ```bash
    npm start
    ```

---

### 👨‍💻 Developed By
**Mohammad Abed Azim**
- [LinkedIn](https://www.linkedin.com/in/mohammad-abed-azim/)
- [GitHub](https://github.com/the-abed)

---
© 2025 UrbanPulse API. Securely powering smarter cities.