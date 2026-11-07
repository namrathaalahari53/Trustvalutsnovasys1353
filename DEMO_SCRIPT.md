# TrustVault Evaluation & Demonstration Script

Follow this step-by-step walkthrough to verify all core security guarantees of TrustVault.

---

### Step 1: Bootstrap & Account Inspection
1. Open the TrustVault application in your browser.
2. Observe the clean enterprise login screen with quick-fill buttons for demo credentials.
3. Click the **Admin** button to pre-fill `admin@trustvault.local` / `TrustVault2026!Admin#`.
4. Click **Sign In**.
5. Observe the Dashboard displaying active metrics, total audit records, and the green `VALID` audit integrity badge.
6. Click **User Management** in the sidebar. Note that Alice and Bob are already registered.

---

### Step 2: Uploading a Confidential Document (Alice)
1. Click the red logout icon in the top right bar.
2. Click **Alice (User A)** to fill Alice's credentials and log in.
3. Click **Upload Document** in the sidebar.
4. Drag and drop or select a confidential test file (e.g. `contract.pdf` or `financials.txt`).
5. Enter Title: `Project Titan Confidential Agreement`.
6. Click **Upload & Encrypt**.
7. Observe the document appearing in **My Documents** with its SHA-256 hash badge and file size.
8. Click **Details** on the document to view full technical metadata:
   - Original filename
   - Storage identifier
   - SHA-256 checksum with Copy button
   - Embedded audit log showing the upload event!

---

### Step 3: Verifying IDOR Isolation (Bob Cannot Access Alice's File)
1. Log out as Alice.
2. Log in as **Bob (User B)**.
3. Observe **My Documents** is empty.
4. Observe **Shared With Me** is empty.
5. In your browser console or URL bar, Bob attempts to directly fetch Alice's document ID:
   `fetch('/api/documents/' + alice_doc_id)`
6. Observe response: `403 Forbidden` or `404 Not Found`. Access is completely blocked!

---

### Step 4: Authorized Sharing
1. Log back in as **Alice**.
2. Go to **My Documents** and click **Share** on `Project Titan Confidential Agreement`.
3. In the Collaborator email field, enter `bob@trustvault.local`.
4. Select `READ ONLY` from the dropdown and click **Grant**.
5. Log out as Alice and log back in as **Bob**.
6. Click **Shared With Me**. The document is now visible with a blue `READ` badge!
7. Click the download button. The file downloads successfully!

---

### Step 5: Immediate Revocation Workflow
1. Log back in as **Alice**.
2. Click **Share** on `Project Titan Confidential Agreement`.
3. Locate `bob@trustvault.local` in the collaborators table.
4. Click **Revoke Immediately** and confirm the dialog.
5. Log back in as **Bob**.
6. Click **Shared With Me**: the document is gone.
7. Attempt to open or download the direct document URL:
   `http://localhost:3000/api/documents/<alice_doc_id>/download`
8. **Result**: HTTP `403 Forbidden` / `404 Not Found`. Access is denied instantly!

---

### Step 6: Tamper-Evident SHA-256 Audit Chain Verification
1. Log back in as **Admin**.
2. Navigate to **Audit History** in the sidebar.
3. Observe the contiguous sequence of events:
   - Document upload
   - Permission grant
   - Document read / download by Bob
   - Permission revocation by Alice
   - Denied access attempt by Bob (`ACCESS_DENIED`)
4. Click any event's **Hash** button to inspect:
   - Previous block hash $H_{i-1}$
   - Current block hash $H_i = \text{SHA256}(\text{CanonicalPayload} \parallel H_{i-1})$
5. Click **Verify Chain Integrity** at the top.
6. Observe the modal report confirming all historical events have been re-hashed and verified with 0 broken links!
