// ─── Firebase Configuration ────────────────────────────────────────────────
// This file centralises all Firebase connection parameters.
// Replace placeholder values with your project's actual credentials from:
//   Firebase Console → Project Settings → General → Your apps → Web app
// ────────────────────────────────────────────────────────────────────────────

const firebaseConfig = {
  apiKey: "AIzaSyDajo-JsqnnpWi7gKD_wcZrFZ0PfUXeiNU",
  authDomain: "your-warden.firebaseapp.com",
  databaseURL: "https://your-warden-default-rtdb.firebaseio.com",
  projectId: "your-warden",
  storageBucket: "your-warden.firebasestorage.app",
  messagingSenderId: "16705156997",
  appId: "1:16705156997:web:bdf3da6afb2ecd6eefb6ec",
  measurementId: "G-8PXP4GZ152"
};

export { firebaseConfig };
