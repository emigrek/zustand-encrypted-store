# 🔐 Zustand + Iron Session Encrypted Storage Guide

This guide demonstrates how to securely persist Zustand state using:

- `QuickCrypt` (WebCrypto-based encryption)
- `iron-session` (server-side session that stores encryption key)
- `localStorage` (only for encrypted payloads)
- Custom `PersistStorage<T>` adapter for Zustand

---

## 📦 What it Does

- Sensitive app state (e.g., shopping basket) is **encrypted on the server**.
- Only the **encryption key is stored in a secure session cookie** (`HTTP-only`).
- The **encrypted state is stored in `localStorage`** on the client — useless without the session key.
- Zustand automatically loads and saves via `/api/encrypt` and `/api/decrypt`.

---

## 🧩 Files

### 1. `quick-crypt.ts`

```ts
export enum QCError {
  MALFORMED_INPUT = "MALFORMED_INPUT",
  INVALID_VERSION_HEADER = "INVALID_VERSION_HEADER",
  TRANSCODER_FAILURE = "TRANSCODER_FAILURE",
  MESSAGE_AUTHENTICATION_FAILURE = "MESSAGE_AUTHENTICATION_FAILURE",
}

/** No-brainer secure cryptography implementation for any kind of data */
export class QuickCryptError implements Error {
  name: string;
  message: string;
  cause?: unknown;

  constructor(id: QCError, message: string, cause?: unknown) {
    this.name = id as string;
    this.message = message;
    this.cause = cause;
  }
}

export class QuickCrypt {
  private static readonly ENCODING = "utf-8";
  private static readonly VERSION_HEADER = "qc2";
  private static readonly TRAILER = "$";
  private static readonly SEPARATOR = ":";

  // Wersja przeglądarkowa nie korzysta z ENV
  private static readonly SALT = new TextEncoder().encode("static_salt");
  private static readonly ITERATIONS = 100000;
  private static readonly HASH = "SHA-256";
  private static readonly ALGORITHM = {
    name: "AES-GCM",
    length: 256,
  };

  private static async deriveKey(
    passphrase: string,
    iv: Uint8Array
  ): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: this.SALT,
        iterations: this.ITERATIONS,
        hash: this.HASH,
      },
      baseKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"]
    );
  }

  public static async wrap<T>(data: T, passphrase: string): Promise<string> {
    const enc = new TextEncoder();
    const strData = typeof data === "string" ? data : JSON.stringify(data);
    const encoded = enc.encode(strData);

    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV dla AES-GCM
    const key = await this.deriveKey(passphrase, iv);

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      key,
      encoded
    );

    const parts = [
      this.VERSION_HEADER,
      "string", // typ
      btoa(String.fromCharCode(...iv)),
      btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
      this.TRAILER,
    ];

    return parts.join(this.SEPARATOR);
  }

  public static async unwrap<T>(
    wrapped: string,
    passphrase: string
  ): Promise<T> {
    const parts = wrapped.split(this.SEPARATOR);
    if (
      parts.length !== 5 ||
      parts[0] !== this.VERSION_HEADER ||
      parts[4] !== this.TRAILER
    ) {
      throw new Error("Invalid format");
    }

    const [, type, ivBase64, dataBase64] = parts;
    const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(dataBase64), (c) =>
      c.charCodeAt(0)
    );

    const key = await this.deriveKey(passphrase, iv);

    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        },
        key,
        ciphertext
      );

      const decoded = new TextDecoder().decode(decrypted);

      if (type === "string") return decoded as T;
      return JSON.parse(decoded) as T;
    } catch {
      throw new Error("Decryption failed");
    }
  }
}
```

---

### 2. `session.ts`

```ts
import { SessionOptions, getIronSession } from "iron-session";
import { NextApiHandler, NextApiResponse } from "next";
import { SessionData, WithIronSessionRequest } from "./types";

export const sessionOptions: SessionOptions = {
  password: process.env.SESSION_SECRET!,
  cookieName: "myapp.session",
  cookieOptions: {
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
};

export function withSession(
  handler: (
    req: WithIronSessionRequest,
    res: NextApiResponse
  ) => Promise<void | unknown>
): NextApiHandler {
  return async (req, res) => {
    const session = await getIronSession<SessionData>(req, res, sessionOptions);
    (req as WithIronSessionRequest).session = session;
    return handler(req as WithIronSessionRequest, res);
  };
}
```

---

### 3. `pages/api/encrypt.ts`

```ts
import { withSession } from "@/lib/session";
import { QuickCrypt } from "@/lib/quick-crypt";
import { WithIronSessionRequest } from "@/lib/types";
import { NextApiResponse } from "next";

export default withSession(
  async (req: WithIronSessionRequest, res: NextApiResponse) => {
    if (!req.body) return res.status(400).json({ error: "Missing payload" });

    if (!req.session.encryptionKey) {
      req.session.encryptionKey = crypto.randomUUID();
      await req.session.save();
    }

    try {
      const encrypted = await QuickCrypt.wrap(
        JSON.stringify(req.body),
        req.session.encryptionKey
      );
      return res.status(200).json({ encrypted });
    } catch {
      return res.status(500).json({ error: "Encryption failed" });
    }
  }
);
```

---

### 4. `pages/api/decrypt.ts`

```ts
import { withSession } from "@/lib/session";
import { QuickCrypt } from "@/lib/quick-crypt";
import { WithIronSessionRequest } from "@/lib/types";

export default withSession(async (req: WithIronSessionRequest, res) => {
  const key = req.session.encryptionKey;
  const encrypted = req.body?.encrypted;

  if (!key) return res.status(403).json({ error: "Session expired" });
  if (!encrypted)
    return res.status(400).json({ error: "Missing encrypted payload" });

  try {
    const decryptedStr = await QuickCrypt.unwrap<string>(encrypted, key);
    const parsed = JSON.parse(decryptedStr);
    return res.status(200).json(parsed);
  } catch {
    return res.status(400).json({ error: "Decryption failed" });
  }
});
```

---

### 5. `encrypted-storage.ts`

```ts
import { PersistStorage, StorageValue } from "zustand/middleware";

const STORAGE_KEY = "state";

export function createEncryptedStorage<T>(): PersistStorage<T> {
  return {
    async getItem(): Promise<StorageValue<T> | null> {
      const encrypted = localStorage.getItem(STORAGE_KEY);
      if (!encrypted) return null;

      try {
        const res = await fetch("/api/decrypt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ encrypted }),
        });

        if (!res.ok) return null;

        const data = await res.json();
        if (typeof data === "object" && "state" in data && "version" in data) {
          return data;
        }

        return null;
      } catch (err) {
        localStorage.removeItem(STORAGE_KEY);
        console.warn("Decrypt failed:", err);
        return null;
      }
    },

    async setItem(name: string, value: StorageValue<T>): Promise<void> {
      try {
        const res = await fetch("/api/encrypt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(value),
        });

        const data = await res.json();
        if (data.encrypted) {
          localStorage.setItem(STORAGE_KEY, data.encrypted);
        }
      } catch (err) {
        console.warn("Encrypt failed:", err);
      }
    },

    async removeItem(): Promise<void> {
      localStorage.removeItem(STORAGE_KEY);
    },
  };
}
```

---

### 6. `store.ts`

```ts
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { createEncryptedStorage } from "./encrypted-storage";

interface StoreState {
  step: number;
  setStep: (step: number) => void;
}

const useStore = create<StoreState>()(
  persist(
    (set, get) => ({
      step: 0,
      setStep: (step) => set({ step }),
    }),
    {
      name: "state",
      storage: createEncryptedStorage<StoreState>(),
    }
  )
);

export default useStore;
```

---

## ✅ How to Use

### 1. Install dependencies

```bash
npm install iron-session
```

### 2. Add `.env.local`

```env
SESSION_SECRET=your-strong-random-secret
```

> Generate a secure value with `openssl rand -base64 32`

---

## 🔐 Security Benefits

- 🔑 Encryption key never leaves the server
- 🧾 Encrypted payload is useless without the session
- ❌ Resistant to XSS (no key in JS)
- ❌ Resistant to CSRF with `sameSite` + JSON headers
- 💣 Session expiration automatically resets client state fallback

---

## 💡 Recommendations

- Extend session data with `expiresAt` to control key rotation
- Add CSRF token validation if your app is not fully JSON API
- Use `migrate()` and `version` in Zustand persist for upgrades
