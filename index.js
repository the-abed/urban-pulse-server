require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const crypto = require("crypto");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const admin = require("firebase-admin");
const fs = require("fs");
const { url } = require("inspector");
const { default: Stripe } = require("stripe");

const port = process.env.PORT || 5000;

// Initialize Firebase Admin SDK
try {
  const serviceAccount = JSON.parse(
    fs.readFileSync(process.env.FIREBASE_ADMIN_SDK_PATH, "utf-8")
  );
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} catch (error) {
  console.error("Failed to initialize Firebase Admin SDK:", error.message);
}

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB URI and Client setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@simplecrudserver.fyfvvbn.mongodb.net/?appName=simpleCRUDserver`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// -------------------------------
// 🔐 Tracking ID Generator
// -------------------------------
function generateTrackingId() {
  const prefix = "URP";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `${prefix}-${date}-${random}`;
}

// -------------------------------
// 🔥 MIDDLEWARE: Verify Firebase Token & Attach User Role (Challenge Task #1)
// -------------------------------
const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: "Unauthorized access" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    
    // Always use the email from the decoded token for security
    const email = decodedToken.email;

    const usersCollection = client.db("urbanPulse_db").collection("users");
    const user = await usersCollection.findOne({ email: email });

    if (!user) {
      return res.status(404).send({ message: "User record not found" });
    }

    // ATTACH EVERYTHING TO THE REQ OBJECT
    req.user_email = user.email;
    req.user_role = user.role;      // This will be "citizen"
    req.is_blocked = user.isBlocked; // This will be false
    
    next();
  } catch (error) {
    console.error("Auth Error:", error);
    return res.status(401).send({ message: "Invalid Token" });
  }
};

// -------------------------------
// 🔒 ROLE MIDDLEWARE (Challenge Task #1)
// -------------------------------
// Admin only
const verifyAdmin = (req, res, next) => {
  if (req.user_role !== "admin") {
    return res.status(403).send({ message: "Forbidden: Admin access required" });
  }
  next();
};

// Staff (Admins usually have staff permissions too)
const verifyStaff = (req, res, next) => {
  if (req.user_role !== "staff" && req.user_role !== "admin") {
    return res.status(403).send({ message: "Forbidden: Staff access required" });
  }
  next();
};

// Citizen (Blocked users are rejected here)
const verifyCitizen = (req, res, next) => {
  // Check if they are blocked first
  if (req.is_blocked === true) {
    return res.status(403).send({ message: "Forbidden: Your account is blocked" });
  }

  // Allow both 'citizen' and 'admin' (Admins usually need to test or act as citizens)
  if (req.user_role === "citizen" || req.user_role === "admin") {
    return next();
  }

  return res.status(403).send({ message: "Forbidden: Citizen access required" });
};

async function run() {
  try {
    await client.connect();
    const db = client.db("urbanPulse_db");

    // Database Collections
    const usersCollection = db.collection("users");
    const staffCollection = db.collection("staff");
    const issuesCollection = db.collection("issues");
    const trackingCollection = db.collection("trackings");
    const paymentsCollection = db.collection("payments"); // New collection for payments

    const logTracking = async ({ issueId, status, updatedBy }) => {
      const log = {
        issueId,
        status,
        details: status.replace("_", " "),
        updatedBy,
        createdAt: new Date(),
      };

      return await trackingCollection.insertOne(log);
    };

    // -------------------------------
    // 🔑 ADMIN UTILITY API
    // -------------------------------
    // Get user role by email (used after login on client-side)
    app.get("/users/role/:email", async (req, res) => {
      const email = req.params.email;
      const user = await usersCollection.findOne({ email });
      if (user) {
        return res.send({
          role: user.role,
          isBlocked: user.isBlocked,
          isPremium: user.isPremium,
        });
      }
      res.status(404).send({ message: "User not found" });
    });

    // -------------------------------
    // 🧑 USERS API
    // -------------------------------
    // Create a new user (Registration)
    app.post("/users", async (req, res) => {
      const user = req.body;
      // Set default role, status, and subscription
      user.role = "citizen";
      user.isBlocked = false;
      user.isPremium = false;
      user.reportCount = 0; // For free user limit
      user.createdAt = new Date();

      const userExist = await usersCollection.findOne({ email: user.email });
      if (userExist) {
        return res.send({ message: "User already exists" });
      }

      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    // Update user profile/status/subscription (Citizen Profile/Admin Management)
app.patch("/users/:email", verifyFBToken, async (req, res) => {
  const email = req.params.email;
  const { displayName, photoURL, isBlocked, role } = req.body;

  // 1. FORBIDDEN CHECK: Only Admin can change sensitive fields
  const isAdminAction = isBlocked !== undefined || role !== undefined;
  if (isAdminAction && req.user_role !== "admin") {
    return res.status(403).send({
      message: "Forbidden: Only admins can manage roles or status.",
    });
  }

  // 2. OWNERSHIP CHECK: Users can only update themselves (unless Admin)
  if (req.user_role !== "admin" && req.user_email !== email) {
    return res.status(403).send({ 
      message: "Forbidden: You can only update your own profile." 
    });
  }

  // 3. DATA FILTERING: Only allow specific fields to be updated
  let updateDoc = {};
  
  if (req.user_role === "admin") {
    // Admins can update everything sent
    if (displayName) updateDoc.displayName = displayName;
    if (photoURL) updateDoc.photoURL = photoURL;
    if (role) updateDoc.role = role;
    if (isBlocked !== undefined) updateDoc.isBlocked = isBlocked;
  } else {
    // Citizens can ONLY update these two fields
    if (displayName) updateDoc.displayName = displayName;
    if (photoURL) updateDoc.photoURL = photoURL;
  }

  // If no valid fields were provided, stop here
  if (Object.keys(updateDoc).length === 0) {
    return res.status(400).send({ message: "No valid fields provided for update." });
  }

  try {
    const result = await usersCollection.updateOne(
      { email: email },
      { $set: updateDoc }
    );
    res.send(result);
  } catch (error) {
    console.error("Profile Update Error:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

    // -------------------------------
    // 🐞 ISSUES API (Public & Shared Routes)
    // -------------------------------
    // GET all issues (Public with filtering, searching, pagination)
    app.get("/issues", async (req, res) => {
      const {
        category,
        status,
        priority,
        search,
        page = 1,
        limit = 10,
      } = req.query;
      const query = {};
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const skip = (pageNum - 1) * limitNum;

      // 🔍 Server-side Filtering
      if (category) query.category = category;
      if (status) query.status = status;
      if (priority) query.priority = priority;

      // 🔎 Server-side Search (Challenge Task #3)
      if (search) {
        const searchRegex = { $regex: search, $options: "i" };
        query.$or = [
          { title: searchRegex },
          { category: searchRegex },
          { location: searchRegex },
        ];
      }

      // Always prioritize boosted issues
      const sort = { boosted: -1, createdAt: -1 };

      try {
        const issues = await issuesCollection
          .find(query)
          .sort(sort)
          .skip(skip)
          .limit(limitNum)
          .toArray();

        const totalIssues = await issuesCollection.countDocuments(query);

        res.send({
          issues,
          totalIssues,
          currentPage: pageNum,
          totalPages: Math.ceil(totalIssues / limitNum),
        });
      } catch (error) {
        console.error("Error fetching issues:", error);
        res.status(500).send({ message: "Failed to fetch issues" });
      }
    });

    // Get issue by id (Private Route)
    app.get("/issues/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: "Invalid Issue ID" });
      }
      try {
        const result = await issuesCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!result)
          return res.status(404).send({ message: "Issue not found" });
        res.send(result);
      } catch (error) {
        res.status(400).send({ message: "Invalid Issue ID" });
      }
    });

    
    app.patch("/issue/:id/upvote", verifyFBToken, async (req, res) => {
      const issueId = req.params.id;
      if (!ObjectId.isValid(issueId)) {
        return res.status(400).send({ message: "Invalid issue ID" });
      }
      const userEmail = req.user_email;

      try {
        // 1. Fetch the issue to check ownership
        const issue = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
        });

        if (!issue) return res.status(404).send({ message: "Issue not found" });

        // 2. Requirement: Users cannot upvote their own issue
        if (issue.reporterEmail === userEmail) {
          return res
            .status(403)
            .send({ message: "Cannot upvote your own issue" });
        }

        // 3. Atomic Update: Only update if userEmail is NOT in the upvoters array
        // This prevents double-voting even if the frontend fails to disable the button
        const result = await issuesCollection.updateOne(
          {
            _id: new ObjectId(issueId),
            upvoters: { $ne: userEmail }, // "Not Equal": only update if user hasn't voted
          },
          {
            $inc: { upvotes: 1 },
            $push: { upvoters: userEmail },
          }
        );

        if (result.matchedCount === 0) {
          return res
            .status(400)
            .send({ message: "Already upvoted or issue not found" });
        }

        res.send({ success: true, message: "Upvote added" });
      } catch (error) {
        res.status(500).send({ message: "Internal server error" });
      }
    });

    //Payment apis with stripe
    app.post("/create-checkout-session", async (req, res) => {
      const boostInfo = req.body;
      console.log("boostInfo:", boostInfo);
      const amount = boostInfo.amount;
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: amount,
              product_data: {
                name: `Boost Issue for ${amount} USD`,
                description: "Boost Issue",
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          issueId: boostInfo.issueId,
          issueTitle: boostInfo.issueTitle,
          trackingId: boostInfo.trackingId,
          reporterEmail:
            boostInfo.reporterEmail || boostInfo.issueReporterEmail,
        },
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-canceled`,
      });
      res.send({ url: session.url });
    });

    // After Stripe payment success → update parcel + save payment info

    app.patch("/payment-success", async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        console.log("Received sessionId:", sessionId);

        if (!sessionId || typeof sessionId !== "string") {
          console.log("Invalid session ID");
          return res.status(400).send({ message: "Invalid session ID" });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);
        console.log("Session payment_status:", session.payment_status);
        console.log("Session metadata:", session.metadata);

        if (session.payment_status !== "paid") {
          console.log("Payment not successful");
          return res.status(400).send({ message: "Payment not successful" });
        }

        const transactionId = session.payment_intent;
        const trackingId = session.metadata?.trackingId;
        const issueId = session.metadata?.issueId;

        // ✅ Validate metadata
        if (!issueId || !ObjectId.isValid(issueId)) {
          return res
            .status(400)
            .send({ message: "Invalid issue ID in metadata" });
        }

        // ✅ Prevent duplicate payment
        const paymentExists = await paymentsCollection.findOne({
          transactionId,
        });
        console.log("paymentExists:", !!paymentExists);
        if (paymentExists) {
          return res.status(200).send({
            success: true,
            message: "Payment already processed",
            transactionId,
            trackingId: paymentExists.trackingId,
          });
        }

        // ✅ Update issue boosted status
        const issueUpdateResult = await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $set: {
              boosted: true,
              paymentStatus: "paid",
            },
          }
        );
        console.log("issueUpdateResult:", issueUpdateResult);

        if (issueUpdateResult.matchedCount === 0) {
          return res.status(404).send({ message: "Issue not found" });
        }

        // ✅ Save payment
        const payment = {
          amount: session.amount_total,
          transactionId,
          issueId,
          issueName: session.metadata.issueTitle,
          reporterEmail: session.metadata.reporterEmail,
          currency: session.currency,
          paymentStatus: session.payment_status,
          paidAt: new Date(),
          trackingId,
        };

        await paymentsCollection.insertOne(payment);
        console.log("Payment inserted for transactionId:", transactionId);

        return res.send({
          success: true,
          message: "Payment successful & issue boosted",
          transactionId,
          trackingId,
        });
      } catch (error) {
        console.error("Payment Success Error:", error);
        return res.status(500).send({ message: "Internal server error" });
      }
    });

    // GET user role by email (Protected)
    app.get("/users/:email/role", async (req, res) => {
      const email = req.params.email;
      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }
      res.send({ role: user.role || "user" });
    });

    // -------------------------------
    // 🧑 CITIZEN DASHBOARD APIs
    // -------------------------------

    // Create an issue (Citizen only)
   // Create an issue (Citizen only)
    app.post("/issues/report", verifyFBToken, verifyCitizen, async (req, res) => {
      if (req.is_blocked) {
        return res.status(403).send({
          message: "Your account is blocked and cannot report issues.",
        });
      }

      const issue = req.body;
      const user = await usersCollection.findOne({ email: req.user_email });

      // ❌ Free user issue limit check
      // if (!req.is_premium && user.reportCount >= 3) {
      //   return res.status(400).send({
      //     message:
      //       "Free user limit reached (3 issues). Please subscribe for unlimited reports.",
      //   });
      // }

      issue.trackingId = generateTrackingId();
      issue.createdAt = new Date();
      issue.status = "pending";
      issue.upvotes = 0;
      issue.upvoters = []; // Array of emails who upvoted
      issue.assignedStaff = null;

      // 👇 default values
      issue.priority = "normal";
      issue.boosted = false;
      issue.timeline = [
        {
          status: "Pending",
          message: "Issue reported by citizen.",
          updatedBy: "Citizen",
          reporterEmail: issue.reporterEmail,
          date: new Date(),
        },
      ];

      const result = await issuesCollection.insertOne(issue);

      // ➕ Increment report count for citizen
      await usersCollection.updateOne(
        { email: req.user_email },
        { $inc: { reportCount: 1 } }
      );

      res.send(result);
    });

    // GET my issues (Citizen Dashboard)
// GET your own reported issues
app.get("/issues/my/:email", verifyFBToken, verifyCitizen, async (req, res) => {
    try {
        const emailFromToken = req.user_email;

        // Log to verify middleware is working
        console.log("Fetching issues for email:", emailFromToken);

        if (!emailFromToken) {
            return res.status(400).send({ message: "Invalid user email in token" });
        }

        // IMPORTANT: Ensure your DB field name is 'email' 
        // match what you used in app.post("/issues/report")
        const query = { email: emailFromToken };
     

        const result = await issuesCollection
            .find(query)
            .sort({ createdAt: -1 })
            .toArray();

        // Log the result count
        console.log(`Found ${result.length} issues for ${emailFromToken}`);
        
        res.send(result);
    } catch (error) {
        console.error("Database Error:", error);
        res.status(500).send({ message: "Internal Server Error", error: error.message });
    }
});

    // Edit an issue (Citizen only)
app.patch("/issues/my/:id", verifyFBToken, verifyCitizen, async (req, res) => {
    const issueId = req.params.id;
    const { title, description, category, district, upazila } = req.body;

    // Filter the body so we ONLY update specific allowed fields
    const updateDoc = {};
    if (title) updateDoc.title = title;
    if (description) updateDoc.description = description;
    if (category) updateDoc.category = category;
    if (district) updateDoc.district = district;
    if (upazila) updateDoc.upazila = upazila;

    try {
        const result = await issuesCollection.updateOne(
            { _id: new ObjectId(issueId) },
            { $set: updateDoc }
        );

        if (result.modifiedCount > 0) {
            res.send({ success: true, message: "Updated successfully" });
        } else {
            res.status(400).send({ message: "No changes made to the document" });
        }
    } catch (error) {
        res.status(500).send({ message: "Update failed", error: error.message });
    }
});
    // Delete an issue (Citizen only)
app.delete("/issues/my/:id", verifyFBToken, async (req, res) => {
  const issueId = req.params.id;
  const userEmail = req.user_email; // From verifyFBToken

  const issue = await issuesCollection.findOne({
    _id: new ObjectId(issueId),
  });

  if (!issue) return res.status(404).send({ message: "Issue not found" });

  // 🔒 CRITICAL FIX: Change reporterEmail to email
  // Because in your ReportIssue logic, you saved it as 'email'
  if (issue.email !== userEmail) {
    return res.status(403).send({ 
      message: `Forbidden: You (${userEmail}) do not own this issue (${issue.email})` 
    });
  }

  const result = await issuesCollection.deleteOne({
    _id: new ObjectId(issueId),
  });
  res.send(result);
});


    // app.patch(
    //   "/issues/:id/boost",
    //   verifyFBToken,
    //   verifyCitizen,
    //   async (req, res) => {
    //     const issueId = req.params.id;
    //     const userEmail = req.user_email;

    //     const issue = await issuesCollection.findOne({
    //       _id: new ObjectId(issueId),
    //     });

    //     if (!issue) return res.status(404).send({ message: "Issue not found" });
    //     if (issue.reporterEmail !== userEmail)
    //       return res.status(403).send({ message: "Forbidden" });
    //     if (issue.boosted)
    //       return res.status(400).send({ message: "Issue already boosted" });

    //     // 💡 Placeholder for actual payment verification (e.g., Stripe/SSLCommerz webhook)
    //     // For now, assume payment success:
    //     const paymentAmount = 100; // 100tk per issue boost

    //     const boostRecord = {
    //       status: issue.status, // Status doesn't change on boost
    //       message: `Priority boosted by citizen (Payment: ${paymentAmount}tk)`,
    //       updatedBy: "Citizen",
    //       date: new Date(),
    //     };

    //     // ➕ Record Payment
    //     await paymentsCollection.insertOne({
    //       type: "Issue Boost",
    //       issueId: new ObjectId(issueId),
    //       email: userEmail,
    //       amount: paymentAmount,
    //       date: new Date(),
    //     });

    //     const result = await issuesCollection.updateOne(
    //       { _id: new ObjectId(issueId) },
    //       {
    //         $set: {
    //           priority: "high",
    //           boosted: true,
    //         },
    //         $push: {
    //           timeline: boostRecord,
    //         },
    //       }
    //     );

    //     res.send({ success: true, result });
    //   }
    // );

    // -------------------------------
    // 🛠️ STAFF DASHBOARD APIs
    // -------------------------------

    // GET staff's assigned issues
    app.get("/staff/issues", verifyFBToken, verifyStaff, async (req, res) => {
      const query = { "assignedStaff.email": req.user_email };
      // Boosted issues should appear above normal ones
      const cursor = issuesCollection
        .find(query)
        .sort({ boosted: -1, createdAt: -1 });
      const result = await cursor.toArray();
      res.send(result);
    });

    // citizen stats
    app.get("/citizen-stats", verifyFBToken, verifyCitizen, async (req, res) => {
    try {
        const email = req.user_email;

        const stats = await issuesCollection.aggregate([
            { $match: { email: email } }, // Filter for this specific citizen
            {
                $facet: {
                    // Part 1: Status Counts
                    issueStats: [
                        {
                            $group: {
                                _id: "$status",
                                count: { $sum: 1 }
                            }
                        }
                    ],
                    // Part 2: Total Payments (from a different collection or embedded)
                    paymentStats: [
                        {
                            $lookup: {
                                from: "payments", // Assuming you have a payments collection
                                localField: "email",
                                foreignField: "email",
                                as: "userPayments"
                            }
                        },
                        { $unwind: { path: "$userPayments", preserveNullAndEmptyArrays: true } },
                        {
                            $group: {
                                _id: null,
                                totalPaid: { $sum: "$userPayments.amount" }
                            }
                        }
                    ]
                }
            }
        ]).toArray();

        // Format the data for easy consumption by the frontend
        const result = stats[0];
        const formattedStats = {
            total: result.issueStats.reduce((acc, curr) => acc + curr.count, 0),
            pending: result.issueStats.find(s => s._id === 'pending')?.count || 0,
            inProgress: result.issueStats.find(s => s._id === 'in-progress')?.count || 0,
            resolved: result.issueStats.find(s => s._id === 'resolved')?.count || 0,
            totalPayments: result.paymentStats[0]?.totalPaid || 0
        };

        res.send(formattedStats);
    } catch (error) {
        res.status(500).send({ message: "Dashboard error", error: error.message });
    }
});

    // -------------------------------
    // 🛠️ STAFF DASHBOARD APIs
    // -------------------------------

    // Update issue status (Staff only)
    app.patch(
      "/staff/issues/:id/status",
      verifyFBToken,
      verifyStaff,
      async (req, res) => {
        try {
          const issueId = req.params.id;
          if (!ObjectId.isValid(issueId)) {
            return res.status(400).send({ message: "Invalid issue ID" });
          }
          const { newStatus, note } = req.body;
          const staffEmail = req.user_email;

          if (!newStatus) {
            return res.status(400).send({ message: "newStatus is required" });
          }

          const issue = await issuesCollection.findOne({
            _id: new ObjectId(issueId),
          });

          if (!issue) {
            return res.status(404).send({ message: "Issue not found" });
          }

          // 🔒 Authorization
          if (
            issue.assignedStaff?.email !== staffEmail &&
            req.user_role !== "admin"
          ) {
            return res
              .status(403)
              .send({ message: "Forbidden: Not assigned to this issue" });
          }

          /* -----------------------------
         Status transition validation
      ----------------------------- */
          const STATUS_FLOW = {
            assigned: ["accept"],
            accept: ["in_progress"],
            in_progress: ["resolved"],
            resolved: ["closed"],
            closed: [],
          };

          const allowedNext = STATUS_FLOW[issue.status] || [];
          if (!allowedNext.includes(newStatus)) {
            return res.status(400).send({
              message: `Cannot change status from ${issue.status} to ${newStatus}`,
            });
          }

          /* -----------------------------
         Update issue timeline
      ----------------------------- */
          const timelineRecord = {
            status: newStatus,
            message: note || `Status updated to ${newStatus.replace("_", " ")}`,
            updatedBy: req.user_role === "admin" ? "Admin" : "Staff",
            date: new Date(),
          };

          await issuesCollection.updateOne(
            { _id: new ObjectId(issueId) },
            {
              $set: { status: newStatus },
              $push: { timeline: timelineRecord },
            }
          );

          /* -----------------------------
         🔄 Update staff status
      ----------------------------- */
          if (newStatus === "accept") {
            await staffCollection.updateOne(
              { email: staffEmail },
              { $set: { status: "in_work" } }
            );
          }

          if (newStatus === "closed") {
            await staffCollection.updateOne(
              { email: staffEmail },
              { $set: { status: "available" } }
            );
          }

          // 🔥 Track status change
          await logTracking({
            issueId: new ObjectId(issueId),
            status: newStatus,
            updatedBy: req.user_role === "admin" ? "Admin" : "Staff",
          });

          res.send({
            message: "Issue status & staff status updated successfully",
          });
        } catch (error) {
          console.error("Status update error:", error);
          res.status(500).send({ message: "Failed to update status" });
        }
      }
    );

    // -------------------------------
    // 👑 ADMIN DASHBOARD APIs
    // -------------------------------

    // GET all citizens (for Manage Users)
    app.get(
      "/admin/users/citizens",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const query = { role: "citizen" };
        const cursor = usersCollection.find(query).sort({ createdAt: -1 });
        const result = await cursor.toArray();
        res.send(result);
      }
    );

    // GET all staff members (for Manage Staff)
app.get("/staffs", async (req, res) => {
  try {
    const staffs = await staffCollection.find().toArray();

    console.log("Staff count in DB:", staffs.length);
    res.send(staffs);
  } catch (error) {
    console.error("Error fetching staff:", error);
    res.status(500).send({ message: "Failed to fetch staff" });
  }
});




    // Add a new staff member
    app.post("/staff", verifyFBToken, async (req, res) => {
      const staff = req.body;
      const { email, password, name, photo, district, staffUpazila } = staff;

      // 1. Check if user already exists in master user collection
      const userExist = await usersCollection.findOne({ email: email });
      if (userExist)
        return res.status(400).send({ message: "User already exists" });

      try {
        // 2. Create user in Firebase Auth
        const userRecord = await admin.auth().createUser({
          email: email,
          password: password,
          displayName: name,
          photoURL: photo,
        });

        // 3. Prepare common data
        const newUser = {
          uid: userRecord.uid,
          name,
          email,
          photo,
          role: "staff",
          status: "available",
          createdAt: new Date(),
        };

        // 4. Insert into "users" collection (Master list)
        await usersCollection.insertOne(newUser);

        // 5. Insert into "staff" collection (Staff specific list)
        // You can add staff-only fields here like 'salary' or 'designation'
        const staffSpecificData = {
          ...newUser,
          department: "General",
          status: "available",
          district, // Add this
          staffUpazila, // Add this
        };
        const result = await staffCollection.insertOne(staffSpecificData);

        res.send(result);
      } catch (error) {
        console.error("Error creating staff account:", error);
        res
          .status(500)
          .send({ message: "Failed to create account", error: error.message });
      }
    });

    // Delete a staff member
   // DELETE /api/staff/:email
// DELETE /api/staff/:email
app.delete("/api/staff/:email", verifyFBToken, verifyAdmin, async (req, res) => {
  const staffEmail = req.params.email;

  try {
    // 1️⃣ Find staff in usersCollection to get UID
    const staffUser = await usersCollection.findOne({
      email: staffEmail,
      role: "staff",
    });

    if (!staffUser) {
      return res.status(404).json({ message: "Staff user not found in users collection" });
    }

    const uid = staffUser.uid;

    // 2️⃣ Delete user from Firebase Auth
    await admin.auth().deleteUser(uid);

    // 3️⃣ Delete staff from usersCollection
    const deleteUserResult = await usersCollection.deleteOne({
      email: staffEmail,
      role: "staff",
    });

    // 4️⃣ Delete staff from staffCollection
    const deleteStaffResult = await staffCollection.deleteOne({ email: staffEmail });

    // 5️⃣ Unassign staff from any issues
    await issuesCollection.updateMany(
      { "assignedStaff.email": staffEmail },
      { $set: { assignedStaff: null, status: "pending" } } // Reset status to pending
    );

    res.status(200).json({
      message: "Staff deleted successfully",
      deletedFromUsers: deleteUserResult.deletedCount,
      deletedFromStaff: deleteStaffResult.deletedCount,
    });
  } catch (error) {
    console.error("Error deleting staff:", error);
    res.status(500).json({
      message: "Failed to delete staff",
      error: error.message,
    });
  }
});


    // Assign Staff to an Issue (Admin only)
    app.patch(
      "/issues/:id/assign",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const issueId = req.params.id;
        if (!ObjectId.isValid(issueId)) {
          return res.status(400).send({ message: "Invalid issue ID" });
        }
        const { staffEmail, staffName } = req.body; // Staff details to assign

        const issue = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
        });

        if (!issue) return res.status(404).send({ message: "Issue not found" });
        if (issue.assignedStaff)
          return res.status(400).send({ message: "Issue already assigned" });

        const staffRecord = {
          email: staffEmail,
          name: staffName,
          assignedAt: new Date(),
        };

        const timelineRecord = {
          status: "assigned",
          message: `Issue assigned to Staff: ${staffName}`,
          updatedBy: "Admin",
          date: new Date(),
        };

        const result = await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $set: {
              assignedStaff: staffRecord,
              status: "assigned",
            },
            $push: { timeline: timelineRecord },
          }
        );
        await logTracking({
          issueId: new ObjectId(issueId),
          status: "assigned",
          updatedBy: "Admin",
        });

        res.send(result);
      }
    );

    // Reject an issue (Admin only, only if status=pending)
    app.patch(
      "/admin/issues/:id/reject",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const issueId = req.params.id;

        const issue = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
        });

        if (!issue) return res.status(404).send({ message: "Issue not found" });
        if (issue.status.toLowerCase() !== "pending") {
          return res
            .status(400)
            .send({ message: "Only 'Pending' issues can be rejected" });
        }

        const rejectRecord = {
          status: "Rejected",
          message: "Issue rejected by Admin.",
          updatedBy: "Admin",
          date: new Date(),
        };

        const result = await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $set: { status: "rejected" },
            $push: { timeline: rejectRecord },
          }
        );

        res.send(result);
      }
    );

    // Get all assigned issues
    app.get("/staff/issues", verifyFBToken, async (req, res) => {
      try {
        const staffEmail = req.user.email;

        if (!staffEmail) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const issues = await issuesCollection
          .find({
            "assignedStaff.email": staffEmail,
          })
          .sort({ "assignedStaff.assignedAt": -1 })
          .toArray();

        res.send(issues);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch assigned issues" });
      }
    });

    // 💰 Payments API (Admin View)
    app.get("/admin/payments", verifyFBToken, verifyAdmin, async (req, res) => {
      const { type, month } = req.query;
      const query = {};

      if (type) query.type = type;
      // Additional filtering logic for month goes here

      const cursor = paymentsCollection.find(query).sort({ date: -1 });
      const payments = await cursor.toArray();

      res.send(payments);
    });

// payment invoice pdf data by id


    // Single optimized admin dashboard API
    app.get(
  "/admin/dashboard-summary",
  verifyFBToken,
  verifyAdmin,
  async (req, res) => {
    try {
      /* ===============================
         1️⃣ Issues by Status
      =============================== */
      const issueStatusPipeline = [
        {
          $group: {
            _id: "$status",
            count: { $sum: 1 },
          },
        },
        {
          $project: {
            _id: 0,
            status: "$_id",
            count: 1,
          },
        },
      ];

      /* ===============================
         2️⃣ Issues Per Day
      =============================== */
      const issuesPerDayPipeline = [
        {
          $addFields: {
            day: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$createdAt",
              },
            },
          },
        },
        {
          $group: {
            _id: "$day",
            totalIssues: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
      ];

      /* ===============================
         3️⃣ Assigned vs Unassigned
      =============================== */
      const assignmentPipeline = [
        {
          $project: {
            assignmentStatus: {
              $cond: [
                { $ifNull: ["$assignedStaff", false] },
                "assigned",
                "unassigned",
              ],
            },
          },
        },
        {
          $group: {
            _id: "$assignmentStatus",
            count: { $sum: 1 },
          },
        },
        {
          $project: {
            _id: 0,
            status: "$_id",
            count: 1,
          },
        },
      ];

      /* ===============================
         4️⃣ Payment Summary
      =============================== */
      const paymentSummaryPipeline = [
        { $match: { paymentStatus: "paid" } },
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: "$amount" },
            totalPayments: { $sum: 1 },
          },
        },
        {
          $project: {
            _id: 0,
            totalRevenue: 1,
            totalPayments: 1,
          },
        },
      ];

      /* ===============================
         5️⃣ Payments Per Day
      =============================== */
      const paymentsPerDayPipeline = [
        { $match: { paymentStatus: "paid" } },
        {
          $addFields: {
            day: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$paidAt",
              },
            },
          },
        },
        {
          $group: {
            _id: "$day",
            totalAmount: { $sum: "$amount" },
            totalPayments: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
      ];

      /* ===============================
         Execute all aggregations
      =============================== */
      const [
        issueStatus,
        issuesPerDay,
        assignmentSummary,
        paymentSummary,
        paymentsPerDay,
      ] = await Promise.all([
        issuesCollection.aggregate(issueStatusPipeline).toArray(),
        issuesCollection.aggregate(issuesPerDayPipeline).toArray(),
        issuesCollection.aggregate(assignmentPipeline).toArray(),
        paymentsCollection.aggregate(paymentSummaryPipeline).toArray(),
        paymentsCollection.aggregate(paymentsPerDayPipeline).toArray(),
      ]);

      /* ===============================
         Final Dashboard Response
      =============================== */
      res.send({
        issues: {
          byStatus: issueStatus,
          perDay: issuesPerDay,
          assignment: assignmentSummary,
        },
        payments: {
          summary: paymentSummary[0] || {
            totalRevenue: 0,
            totalPayments: 0,
          },
          perDay: paymentsPerDay,
        },
      });
    } catch (error) {
      console.error("Dashboard Summary Error:", error);
      res.status(500).send({ message: "Failed to load dashboard data" });
    }
  }
);


    // -------------------------------
    // PDF GENERATION (Challenge Task #4: Client-side logic assumed, endpoint for data)
    // -------------------------------

    // Get payment details for PDF invoice
    app.get("/payments/invoice/:paymentId", verifyFBToken, async (req, res) => {
      const paymentId = req.params.paymentId;
      if (!ObjectId.isValid(paymentId)) {
        return res.status(400).send({ message: "Invalid payment ID" });
      }
      const payment = await paymentsCollection.findOne({
        _id: new ObjectId(paymentId),
      });

      if (!payment)
        return res.status(404).send({ message: "Payment not found" });

      // 🔒 Only Admin or the payment owner can access
      if (req.user_role !== "admin" && req.user_email !== payment.email) {
        return res.status(403).send({ message: "Forbidden" });
      }

      // Client-side will fetch this data to generate the PDF
      res.send(payment);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Keeps the client open
  }
}
run().catch(console.dir);

// -------------------------------
// ROOT
// -------------------------------
app.get("/", (req, res) => {
  res.send("UrbanPulse Server is running");
});

// -------------------------------
// SERVER
// -------------------------------
app.listen(port, () => {
  console.log(`UrbanPulse Server listening on port ${port}`);
});
