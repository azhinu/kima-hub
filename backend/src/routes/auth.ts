import { Router } from "express";
import { logger } from "../utils/logger";
import bcrypt from "bcrypt";
import { createUser, prisma, updateUserRole } from "../utils/db";
import { z } from "zod";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import {
    requireAuth,
    requireAdmin,
    generateToken,
    generateRefreshToken,
} from "../middleware/auth";
import { encrypt, decrypt } from "../utils/encryption";
import { AUTH_PROVIDERS, AuthType, OidcProvider } from "../utils/auth";
import axios from "axios";


const router = Router();

interface Provider {
    id: string;
    name: string;
    type: string;
    oidcIssuer?: string;
    oidcClientId?: string;
}

// GET /auth/providers - Public endpoint to get configured auth providers
router.get("/providers", async (req, res) => {
    try {
        let providers: Array<Provider> = [];

        AUTH_PROVIDERS.forEach((provider, id) => {
            if (provider.type === AuthType.OIDC) {
                providers.push({
                    id: id,
                    name: provider.name,
                    type: "oidc",
                    oidcIssuer: (provider as OidcProvider).issuer,
                    oidcClientId: (provider as OidcProvider).clientId
                });
            } else if (provider.type === AuthType.CREDENTIALS) {
                providers.push({
                    id: id,
                    name: provider.name,
                    type: "credentials"
                });
            } else {
                console.warn(`Unknown auth provider type for id ${id}`);
            }
        })

        const oidcSkipLogin = process.env.OIDC_SKIP_LOGIN === "true";

        res.json({ providers, oidcSkipLogin });
    } catch (error) {
        console.error("Get auth providers error:", error);
        res.status(500).json({ error: "Failed to get auth providers" });
    }
});

AUTH_PROVIDERS.forEach((provider, id) => {
    if (provider.type !== AuthType.OIDC) return;

    const oidcProvider = provider as OidcProvider;
    const issuer = oidcProvider.issuer;
    const clientId = oidcProvider.clientId;
    const clientSecret = oidcProvider.clientSecret;

    // POST /auth/oidc/login/:id - Accept id_token/access_token OR authorization code + code_verifier from SPA
    router.post('/oidc/login/' + id, async (req, res) => {
        try {
            const { id_token, access_token, code, codeVerifier, redirectUri } = req.body;
            
            console.log(`[OIDC ${id}] Login request received`);
            console.log(`[OIDC ${id}] Has id_token: ${!!id_token}, Has access_token: ${!!access_token}, Has code: ${!!code}`);

            // If code is provided, perform server-side PKCE token exchange
            let finalIdToken: string | undefined = id_token;
            let finalAccessToken: string | undefined = access_token;

            const discoveryResp = await axios.get(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`, { timeout: 5000 });
            const discovery = discoveryResp.data || {};
            const tokenEndpoint = discovery.token_endpoint;
            const userinfoEndpoint = discovery.userinfo_endpoint;

            if (code) {
                if (!tokenEndpoint) return res.status(500).json({ error: 'Provider token endpoint not found' });
                // Exchange code for tokens using client_secret (confidential server)
                const params = new URLSearchParams();
                params.append('grant_type', 'authorization_code');
                params.append('code', code);
                params.append('redirect_uri', redirectUri);
                params.append('client_id', clientId);
                if (clientSecret) params.append('client_secret', clientSecret);
                if (codeVerifier) params.append('code_verifier', codeVerifier);

                const headers: any = { 'Content-Type': 'application/x-www-form-urlencoded' };

                console.log(`[OIDC ${id}] Sending token exchange request to ${tokenEndpoint}`);
                console.log(`[OIDC ${id}] Params:`, params.toString());

                try {
                    const tokenResp = await axios.post(tokenEndpoint, params.toString(), { headers, timeout: 5000 });
                    const tokenData = tokenResp.data || {};
                    finalIdToken = tokenData.id_token;
                    finalAccessToken = tokenData.access_token;
                    console.log(`[OIDC ${id}] Token exchange successful`);
                } catch (tokenErr: any) {
                    console.error(`[OIDC ${id}] Token exchange failed:`, {
                        status: tokenErr.response?.status,
                        statusText: tokenErr.response?.statusText,
                        data: tokenErr.response?.data,
                        message: tokenErr.message
                    });
                    throw tokenErr;
                }
            }

            // Extract claims from id_token or userinfo
            let idClaims: any = {};
            let userinfo: any = {};

            console.log(`[OIDC ${id}] After token exchange: finalIdToken=${!!finalIdToken}, finalAccessToken=${!!finalAccessToken}`);

            if (finalIdToken) {
                try {
                    idClaims = jwt.decode(finalIdToken) || {};
                    console.log(`[OIDC ${id}] Decoded id_token:`, { sub: idClaims.sub, email: idClaims.email, preferred_username: idClaims.preferred_username });
                } catch (e) {
                    console.warn('Failed to decode id_token:', (e as any)?.message || e);
                }
            }

            if ((!idClaims || !idClaims.sub) && finalAccessToken && userinfoEndpoint) {
                try {
                    console.log(`[OIDC ${id}] Fetching userinfo from ${userinfoEndpoint}`);
                    const ui = await axios.get(userinfoEndpoint, { headers: { Authorization: `Bearer ${finalAccessToken}` }, timeout: 5000 });
                    userinfo = ui.data || {};
                    console.log(`[OIDC ${id}] Userinfo fetched:`, { sub: userinfo.sub, email: userinfo.email });
                } catch (e) {
                    console.warn(`[OIDC ${id}] Failed to fetch userinfo with access_token:`, (e as any)?.message || e);
                }
            }

            const merged = { ...idClaims, ...userinfo };
            console.log(`[OIDC ${id}] Merged claims:`, { sub: merged.sub, email: merged.email, preferred_username: merged.preferred_username });
            
            if (!merged.sub) return res.status(400).json({ error: 'No user identifier (sub) returned by provider' });
            if (!merged.email) return res.status(400).json({ error: 'No email returned by provider' });

            const uid = merged.sub;
            const email = merged.email;
            let role = 'user';
            if (oidcProvider.roleField) {
                const roleValue = merged[oidcProvider.roleField];
                console.log(`[OIDC ${id}] Role field '${oidcProvider.roleField}' value:`, roleValue);
                if (!roleValue) return res.status(400).json({ error: `No field '${oidcProvider.roleField}' provided for role in OIDC scope` });
                if (Array.isArray(roleValue) && roleValue.length === 1) role = roleValue[0];
                else if (typeof roleValue === 'string') role = roleValue;
                else return res.status(400).json({ error: `Invalid role value '${roleValue}' provided for role in OIDC scope` });
            }

            // Find or create user
            const username = merged.preferred_username || email;
            console.log(`[OIDC ${id}] Looking for user: username=${username}, email=${email}, uid=${uid}, role=${role}`);
            
            let user = await prisma.user.findFirst({ where: { OR: [{ username }] } });
            console.log(`[OIDC ${id}] User lookup result:`, user ? `found user ${user.id}` : 'no user found');
            if (!user) {
                console.log(`[OIDC ${id}] Creating new user: ${username}`);
                const unusablePassword = crypto.randomBytes(32).toString('hex');
                const unusablePasswordHash = await bcrypt.hash(unusablePassword, 10);
                user = await createUser(username, unusablePasswordHash, role, id, uid);
                console.log(`[OIDC ${id}] User created: ${user.id}`);
            } else if (user.oidcId !== id || user.oidcUid !== uid) {
                console.log(`[OIDC ${id}] User OIDC identity mismatch:`, { existingOidcId: user.oidcId, newOidcId: id, existingOidcUid: user.oidcUid, newOidcUid: uid });
                return res.status(400).json({ error: `User '${username}' exists with different OIDC identity` });
            } else if (user.role !== role) {
                console.log(`[OIDC ${id}] Updating user role: ${user.role} -> ${role}`);
                await updateUserRole(username, role);
            }

            console.log(`[OIDC ${id}] Generating JWT token for user: ${user.id}`);
            const jwtToken = generateToken({ id: user.id, username: user.username, role: user.role, tokenVersion: user.tokenVersion });
            console.log(`[OIDC ${id}] Login successful!`);
            return res.json({ token: jwtToken });
        } catch (err: any) {
            console.error(`[OIDC ${id}] Login failed:`, {
                message: err.message,
                stack: err.stack,
                status: err.response?.status,
                statusText: err.response?.statusText,
                responseData: err.response?.data,
                code: err.code
            });
            return res.status(400).json({ error: 'OIDC login failed', details: err.message });
        }
    });
})

const loginSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1),
});

// Use shared encryption module for 2FA secrets
const encrypt2FASecret = encrypt;
const decrypt2FASecret = decrypt;

// POST /auth/login
router.post("/login", async (req, res) => {
    try {
        logger.debug(`[AUTH] Login attempt for user: ${req.body?.username}`);
        const { username, password } = loginSchema.parse(req.body);
        const { token } = req.body; // 2FA token if provided

        const user = await prisma.user.findUnique({ where: { username } });

        // Timing-safe: always run bcrypt to prevent username enumeration
        const dummyHash = "$2b$10$invalidhashfortimingsafety.00000000000000000000";
        const valid = await bcrypt.compare(password, user?.passwordHash ?? dummyHash);
        if (!user || !valid) {
            logger.debug(`[AUTH] Invalid credentials for: ${username}`);
            return res.status(401).json({ error: "Invalid credentials" });
        }
        logger.debug(`[AUTH] Password verified for user: ${username}`);

        // Check if 2FA is enabled
        if (user.twoFactorEnabled && user.twoFactorSecret) {
            if (!token) {
                return res.status(200).json({
                    requires2FA: true,
                    message: "2FA token required",
                });
            }

            // Check if it's a recovery code
            const isRecoveryCode = /^[A-F0-9]{8}$/i.test(token);

            if (isRecoveryCode && user.twoFactorRecoveryCodes) {
                const encryptedCodes = user.twoFactorRecoveryCodes;
                const decryptedCodes = decrypt2FASecret(encryptedCodes);
                const hashedCodes = decryptedCodes.split(",");

                const providedHash = crypto
                    .createHash("sha256")
                    .update(token.toUpperCase())
                    .digest("hex");

                const codeIndex = hashedCodes.indexOf(providedHash);
                if (codeIndex === -1) {
                    return res
                        .status(401)
                        .json({ error: "Invalid recovery code" });
                }

                hashedCodes.splice(codeIndex, 1);
                await prisma.user.update({
                    where: { id: user.id },
                    data: {
                        twoFactorRecoveryCodes: encrypt2FASecret(
                            hashedCodes.join(",")
                        ),
                    },
                });
            } else {
                // Verify TOTP token
                const secret = decrypt2FASecret(user.twoFactorSecret);
                const verified = speakeasy.totp.verify({
                    secret,
                    encoding: "base32",
                    token,
                    window: 2,
                });

                if (!verified) {
                    return res.status(401).json({ error: "Invalid 2FA token" });
                }
            }
        }

        // Generate JWT tokens
        const jwtToken = generateToken({
            id: user.id,
            username: user.username,
            role: user.role,
            tokenVersion: user.tokenVersion,
        });
        const refreshToken = generateRefreshToken({
            id: user.id,
            tokenVersion: user.tokenVersion,
        });

        res.json({
            token: jwtToken,
            refreshToken: refreshToken,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
            },
        });
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res
                .status(400)
                .json({ error: "Invalid request", details: err.errors });
        }
        logger.error("Login error:", err);
        res.status(500).json({ error: "Internal error" });
    }
});

// POST /auth/logout - JWT is stateless, logout is handled client-side
router.post("/logout", (req, res) => {
    // With JWT, logout is handled by client removing the token
    // No server-side session to destroy
    res.json({ message: "Logged out" });
});

// POST /auth/refresh - Refresh access token using refresh token
router.post("/refresh", async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: "Refresh token required" });
    }

    try {
        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_SECRET || process.env.SESSION_SECRET!
        ) as any;

        if (decoded.type !== "refresh") {
            return res.status(401).json({ error: "Invalid refresh token" });
        }

        const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: {
                id: true,
                username: true,
                role: true,
                tokenVersion: true,
            },
        });

        if (!user) {
            return res.status(401).json({ error: "User not found" });
        }

        // Validate tokenVersion
        if (decoded.tokenVersion !== user.tokenVersion) {
            return res.status(401).json({ error: "Token invalidated" });
        }

        const newAccessToken = generateToken(user);
        const newRefreshToken = generateRefreshToken(user);

        return res.json({
            token: newAccessToken,
            refreshToken: newRefreshToken,
        });
    } catch (error) {
        return res.status(401).json({ error: "Invalid refresh token" });
    }
});

// GET /auth/me
router.get("/me", requireAuth, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: {
                id: true,
                username: true,
                role: true,
                onboardingComplete: true,
                enrichmentSettings: true,
                createdAt: true,
            },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json(user);
    } catch (error) {
        logger.error("Get current user error:", error);
        res.status(500).json({ error: "Internal error" });
    }
});

// POST /auth/change-password
router.post("/change-password", requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res
                .status(400)
                .json({ error: "Current and new password are required" });
        }

        if (newPassword.length < 6) {
            return res
                .status(400)
                .json({ error: "New password must be at least 6 characters" });
        }

        // Verify current password
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: { id: true, passwordHash: true },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const valid = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!valid) {
            return res
                .status(401)
                .json({ error: "Current password is incorrect" });
        }

        // Update password and increment tokenVersion to invalidate all existing tokens
        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                passwordHash: newPasswordHash,
                tokenVersion: { increment: 1 },
            },
        });

        res.json({ message: "Password changed successfully" });
    } catch (error) {
        logger.error("Change password error:", error);
        res.status(500).json({ error: "Failed to change password" });
    }
});

// GET /auth/users (Admin only)
router.get("/users", requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                username: true,
                role: true,
                onboardingComplete: true,
                createdAt: true,
            },
            orderBy: { createdAt: "asc" },
        });

        res.json(users);
    } catch (error) {
        logger.error("Get users error:", error);
        res.status(500).json({ error: "Failed to get users" });
    }
});

// POST /auth/create-user (Admin only)
router.post("/create-user", requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ error: "Username and password are required" });
        }

        if (password.length < 6) {
            return res
                .status(400)
                .json({ error: "Password must be at least 6 characters" });
        }

        if (role && !["user", "admin"].includes(role)) {
            return res.status(400).json({ error: "Invalid role" });
        }

        // Check if username exists
        const existing = await prisma.user.findUnique({
            where: { username },
        });

        if (existing) {
            return res.status(400).json({ error: "Username already taken" });
        }

        const user = await createUser(username, password, role);

        res.json({
            id: user.id,
            username: user.username,
            role: user.role,
            createdAt: user.createdAt,
        });
    } catch (error) {
        logger.error("Create user error:", error);
        res.status(500).json({ error: "Failed to create user" });
    }
});

// DELETE /auth/users/:id (Admin only)
router.delete("/users/:id", requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Prevent deleting yourself
        if (id === req.user!.id) {
            return res
                .status(400)
                .json({ error: "Cannot delete your own account" });
        }

        // Delete user (cascade will handle related data)
        await prisma.user.delete({
            where: { id },
        });

        res.json({ message: "User deleted successfully" });
    } catch (error: any) {
        logger.error("Delete user error:", error);
        if (error.code === "P2025") {
            return res.status(404).json({ error: "User not found" });
        }
        res.status(500).json({ error: "Failed to delete user" });
    }
});

// POST /auth/2fa/setup - Generate 2FA secret and QR code
router.post("/2fa/setup", requireAuth, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: { username: true, twoFactorEnabled: true },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (user.twoFactorEnabled) {
            return res.status(400).json({ error: "2FA is already enabled" });
        }

        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `Kima (${user.username})`,
            issuer: "Kima",
        });

        // Generate QR code
        const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

        res.json({
            secret: secret.base32,
            qrCode: qrCodeDataUrl,
        });
    } catch (error) {
        logger.error("2FA setup error:", error);
        res.status(500).json({ error: "Failed to setup 2FA" });
    }
});

// POST /auth/2fa/enable - Verify token and enable 2FA
router.post("/2fa/enable", requireAuth, async (req, res) => {
    try {
        const { secret, token } = req.body;

        if (!secret || !token) {
            return res
                .status(400)
                .json({ error: "Secret and token are required" });
        }

        // Verify the token with the secret
        const verified = speakeasy.totp.verify({
            secret,
            encoding: "base32",
            token,
            window: 2,
        });

        if (!verified) {
            return res
                .status(401)
                .json({ error: "Invalid token. Please try again." });
        }

        // Generate 10 recovery codes
        const recoveryCodes: string[] = [];
        const hashedRecoveryCodes: string[] = [];

        for (let i = 0; i < 10; i++) {
            // Generate 8-character alphanumeric code
            const code = crypto.randomBytes(4).toString("hex").toUpperCase();
            recoveryCodes.push(code);
            // Hash the code before storing
            hashedRecoveryCodes.push(
                crypto.createHash("sha256").update(code).digest("hex")
            );
        }

        // Encrypt the hashed codes for storage
        const encryptedRecoveryCodes = encrypt2FASecret(
            hashedRecoveryCodes.join(",")
        );

        // Encrypt and save the secret
        const encryptedSecret = encrypt2FASecret(secret);
        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                twoFactorEnabled: true,
                twoFactorSecret: encryptedSecret,
                twoFactorRecoveryCodes: encryptedRecoveryCodes,
            },
        });

        // Return the plain recovery codes to the user (only time they'll see them)
        res.json({
            message: "2FA enabled successfully",
            recoveryCodes: recoveryCodes,
        });
    } catch (error) {
        logger.error("2FA enable error:", error);
        res.status(500).json({ error: "Failed to enable 2FA" });
    }
});

// POST /auth/2fa/disable - Disable 2FA
router.post("/2fa/disable", requireAuth, async (req, res) => {
    try {
        const { password, token } = req.body;

        if (!password || !token) {
            return res
                .status(400)
                .json({ error: "Password and current 2FA token are required" });
        }

        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: { id: true, passwordHash: true, twoFactorSecret: true },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.passwordHash);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid password" });
        }

        // Verify 2FA token
        if (user.twoFactorSecret) {
            const secret = decrypt2FASecret(user.twoFactorSecret);
            const verified = speakeasy.totp.verify({
                secret,
                encoding: "base32",
                token,
                window: 2,
            });

            if (!verified) {
                return res.status(401).json({ error: "Invalid 2FA token" });
            }
        }

        // Disable 2FA
        await prisma.user.update({
            where: { id: req.user!.id },
            data: {
                twoFactorEnabled: false,
                twoFactorSecret: null,
                twoFactorRecoveryCodes: null,
            },
        });

        res.json({ message: "2FA disabled successfully" });
    } catch (error) {
        logger.error("2FA disable error:", error);
        res.status(500).json({ error: "Failed to disable 2FA" });
    }
});

// GET /auth/2fa/status - Check if 2FA is enabled
router.get("/2fa/status", requireAuth, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user!.id },
            select: { twoFactorEnabled: true },
        });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ enabled: user.twoFactorEnabled });
    } catch (error) {
        logger.error("2FA status error:", error);
        res.status(500).json({ error: "Failed to get 2FA status" });
    }
});

export default router;
