//fork
"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { AUTH_PROVIDERS, AuthProvider, startOIDCLogin, loadAuthConfig } from "@/lib/auth/oidc-client";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import Image from "next/image";
import { Key, Loader2 } from "lucide-react";
import { GalaxyBackground } from "@/components/ui/GalaxyBackground";
import { AuthPageTemplate } from "@/components/auth/AuthPageTemplate";
import Link from "next/link";

interface Artist {
    id: string;
    mbid?: string;
    name: string;
    heroUrl: string | null;
    albumCount?: number;
}

const LOGIN_ERROR_MESSAGES: Record<string, string> = {
  "session_expired": "Your session has expired. Please sign in again.",
  "unauthorized": "You must be signed in to access that page.",
  "account_disabled": "Your account has been disabled.",
  "invalid_token": "Invalid authentication token.",
};
// Separate component to handle search params (needs Suspense boundary)
function LoginErrorHandler({
    setError,
}: {
    setError: (error: string) => void;
}) {
    const searchParams = useSearchParams();

    useEffect(() => {
      const errorCode = searchParams.get("error");
      if (errorCode) {
          const message = LOGIN_ERROR_MESSAGES[errorCode] ?? "An error occurred. Please try again.";
          setError(message);
      }
  }, [searchParams, setError]);

    return null;
}

export default function LoginPage() {
  const { login } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [twoFactorToken, setTwoFactorToken] = useState("");
  const [requires2FA, setRequires2FA] = useState(false);
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isCheckingOnboarding, setIsCheckingOnboarding] = useState(true);
  const [artists, setArtists] = useState<Artist[]>([]);
  const [currentArtistIndex, setCurrentArtistIndex] = useState(0);
  const [showCredentials, setShowCredentials] = useState(false);
  const [providers, setProviders] = useState<AuthProvider[]>([]);
  const [isLoadingProviders, setIsLoadingProviders] = useState(true);
  const [oidcSkipLogin, setOidcSkipLogin] = useState(false);

  // Defense in depth: Check if onboarding is needed
  // If no users exist, redirect to onboarding instead of showing login
  useEffect(() => {
      const checkOnboarding = async () => {
          try {
              const status = await api.get<{ hasAccount: boolean }>(
                  "/onboarding/status"
              );
              if (!status.hasAccount) {
                  router.replace("/onboarding");
                  return;
              }
          } catch {
              // If check fails, show login form (fail open)
          }
          setIsCheckingOnboarding(false);
      };
      checkOnboarding();
  }, [router]);

  // Fetch auth providers on mount
  useEffect(() => {
      const fetchProviders = async () => {
          try {
              const authConfig = await loadAuthConfig();
              setProviders(authConfig.providers);
              setOidcSkipLogin(authConfig.oidcSkipLogin);
          } catch (err) {
              console.error("Failed to fetch providers:", err);
          } finally {
              setIsLoadingProviders(false);
          }
      };

      fetchProviders();
  }, []);

  // Auto-redirect to first OIDC provider if OIDC_SKIP_LOGIN is enabled
  useEffect(() => {
      if (isLoadingProviders || providers.length === 0) return;

      console.log("[LoginPage] OIDC_SKIP_LOGIN:", oidcSkipLogin);

      if (oidcSkipLogin) {
          const oidcProviders = providers.filter((p) => p.type === "oidc");
          console.log("[LoginPage] Found OIDC providers:", oidcProviders.length);
          if (oidcProviders.length > 0) {
              console.log("[LoginPage] Auto-redirecting to", oidcProviders[0].name);
              startOIDCLogin(oidcProviders[0]).catch((err) => {
                  console.error("Auto-redirect OIDC login failed:", err);
                  setError("Failed to redirect to OIDC provider");
              });
          }
      }
  }, [isLoadingProviders, providers, oidcSkipLogin]);

  // Fetch featured artists for background rotation
  useEffect(() => {
    const fetchArtists = async () => {
        try {
            // Get recently listened artists (public endpoint or cached data)
            const response = await fetch(
                "/api/library/recently-listened?limit=10"
            );
            if (response.ok) {
                const data = await response.json();
                const artistsWithImages = data.artists.filter(
                    (a: Artist) => a.heroUrl
                );
                setArtists(
                    artistsWithImages.length > 0 ? artistsWithImages : []
                );
            }
            // Silently ignore errors (expected when not authenticated)
        } catch {
            // Fail silently - login page will work without backgrounds
        }
    };

      fetchArtists();
  }, []);

  // Rotate through artists every 5 seconds
  useEffect(() => {
      if (artists.length <= 1) return;

      const interval = setInterval(() => {
          setCurrentArtistIndex((prev) => (prev + 1) % artists.length);
      }, 5000);

      return () => clearInterval(interval);
  }, [artists.length]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
        // First step: Send username and password
        if (!requires2FA) {
            await login(username, password);
            // If we get here, either:
            // 1. Login succeeded (no 2FA)
            // 2. We'll catch the requires2FA response below
        } else {
            // Second step: Send 2FA token
            await login(username, password, twoFactorToken);
            // If successful, login() will redirect
        }
    } catch (err) {
        const errorMsg =
            err instanceof Error ? err.message : "Login failed";

        // Check if 2FA is required
        if (
            errorMsg.includes("2FA token required") ||
            errorMsg.includes("requires2FA")
        ) {
            setRequires2FA(true);
            setError("");
        } else if (
            errorMsg.includes("Invalid 2FA token") ||
            errorMsg.includes("Invalid recovery code")
        ) {
            setError(errorMsg);
            setTwoFactorToken(""); // Clear the token for retry
        } else {
            setError(errorMsg);
            setRequires2FA(false);
            setTwoFactorToken("");
        }
    } finally {
        setIsLoading(false);
    }
};


  const handleOIDCLogin = async (provider: AuthProvider) => {
      try {
          await startOIDCLogin(provider);
      } catch (err) {
          console.error("OIDC login failed:", err);
          const message =
              err instanceof Error && err.message ? err.message : String(err);
          setError(`Failed to start OIDC login: ${message}`);
      }
  };

  const currentArtist = artists[currentArtistIndex];

  // Show loading while checking if onboarding is needed
  if (isCheckingOnboarding) {
      return (
          <div className="min-h-screen flex items-center justify-center bg-black">
              <Loader2 className="w-8 h-8 animate-spin text-white/60" />
          </div>
      );
  }

  return (
      <div className="min-h-screen w-full relative overflow-hidden">
          {/* Handle error from URL params */}
          <Suspense fallback={null}>
              <LoginErrorHandler setError={setError} />
          </Suspense>

          {/* Animated Background with Artist Images */}
          <div className="absolute inset-0 bg-[#000]">
              {/* Subtle accent gradient */}
              <div className="absolute inset-0 bg-gradient-to-br from-[#fca200]/5 via-transparent to-transparent" />

              {/* Ultra-subtle starfield texture (dialed down vs the main app) */}
              <div className="opacity-[0.08]">
                  <GalaxyBackground
                      primaryColor="#fca200"
                      secondaryColor="#fca200"
                  />
              </div>

              {artists.length > 0 && currentArtist?.heroUrl && (
                  <>
                      <div
                          key={currentArtistIndex}
                          className="absolute inset-0 transition-opacity duration-1000"
                      >
                          <Image
                              src={currentArtist.heroUrl}
                              alt={currentArtist.name}
                              fill
                              className="object-cover"
                              priority
                          />
                      </div>
                      {/* Heavy blur overlay */}
                      <div className="absolute inset-0 backdrop-blur-[100px] bg-black/60" />

                      {/* Gradient overlays for depth */}
                      <div className="absolute inset-0 bg-gradient-to-t from-black via-black/50 to-transparent" />
                      <div className="absolute inset-0 bg-gradient-to-b from-black/80 via-transparent to-black/80" />
                  </>
              )}
          </div>

          {/* Artist Info Section - Bottom Left */}
          {currentArtist && (
              <div className="absolute bottom-8 left-8 z-10 text-white max-w-md animate-fade-in">
                  <p className="text-sm font-medium text-white/60 mb-2">
                      Featured Artist
                  </p>
                  <h2 className="text-3xl md:text-4xl font-bold mb-2 drop-shadow-2xl">
                      {currentArtist.name}
                  </h2>
                  {currentArtist.albumCount !== undefined && (
                      <p className="text-white/70 text-sm">
                          {currentArtist.albumCount} album
                          {currentArtist.albumCount !== 1 ? "s" : ""} in your
                          library
                      </p>
                  )}
              </div>
          )}

          {/* Login Form - Centered */}
          <div className="relative z-20 min-h-screen flex items-center justify-center p-4">
              <div className="w-full max-w-md">
                  {/* Logo */}
                  <div className="flex items-center justify-center mb-8">
                      <div className="relative flex gap-3 items-center group">
                          <div className="relative">
                              <div className="absolute inset-0 bg-white/10 blur-xl rounded-full group-hover:bg-white/20 transition-all duration-300" />
                              <Image
                                  src="/assets/images/kima.webp"
                                  alt="Kima"
                                  width={40}
                                  height={40}
                                  className="relative z-10 drop-shadow-2xl"
                              />
                          </div>
                          <span className="text-3xl font-bold bg-gradient-to-r from-white via-white to-gray-200 bg-clip-text text-transparent drop-shadow-2xl">
                              Kima
                          </span>
                      </div>
                  </div>

                  {/* Login Card */}
                  <div className="bg-[#111]/90 rounded-lg p-6 md:p-8 border border-white/10 shadow-xl ">
                      <h1 className="text-2xl font-bold text-white mb-1 text-center">
                          Welcome back
                      </h1>
                      <p className="text-white/60 text-center mb-8">
                          Sign in to continue to Kima
                      </p>

                      {error && (
                          <div className="bg-red-500/10  border border-red-500/30 rounded-lg p-4 text-sm text-red-400 animate-shake">
                              {error}
                          </div>
                      )}

                      {/* OIDC Providers Section - Primary */}
                      {!showCredentials && (
                          <div className="space-y-4">
                              {isLoadingProviders ? (
                                  <div className="flex justify-center py-8">
                                      <Loader2 className="w-6 h-6 animate-spin text-white/60" />
                                  </div>
                              ) : (
                                  <>
                                      {providers
                                          .filter((p) => p.type === "oidc")
                                          .map((provider) => (
                                              <button
                                                  key={provider.id}
                                                  onClick={() =>
                                                      handleOIDCLogin(provider)
                                                  }
                                                  className="w-full px-6 py-4 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-[#fca200]/50 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-3 group"
                                              >
                                                  <svg
                                                      className="w-5 h-5 text-[#fca200]"
                                                      fill="none"
                                                      stroke="currentColor"
                                                      viewBox="0 0 24 24"
                                                  >
                                                      <path
                                                          strokeLinecap="round"
                                                          strokeLinejoin="round"
                                                          strokeWidth={2}
                                                          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                                                      />
                                                  </svg>
                                                  Sign in with {provider.name}
                                              </button>
                                          ))}

                                      {providers.some((p) => p.type === "credentials") && (
                                          <>
                                              {/* Divider */}
                                              <div className="relative py-4">
                                                  <div className="absolute inset-0 flex items-center">
                                                      <div className="w-full border-t border-white/10"></div>
                                                  </div>
                                                  <div className="relative flex justify-center text-sm">
                                                      <span className="px-4 bg-[#111] text-gray-400">
                                                          Or
                                                      </span>
                                                  </div>
                                              </div>

                                              {/* Credentials Toggle */}
                                              <button
                                                  type="button"
                                                  onClick={() => setShowCredentials(true)}
                                                  className="w-full px-6 py-4 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-[#fca200]/50 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-3 group"
                                              >
                                                  <Key className="w-5 h-5 text-[#fca200]" />
                                                  Sign in with Credentials
                                              </button>
                                          </>
                                      )}
                                  </>
                              )}
                          </div>
                      )}

                      {/* Credentials Form - Secondary */}
                      {showCredentials && (
                          <form onSubmit={handleSubmit} className="space-y-4">
                              {/* Step 1: Username & Password */}
                              {!requires2FA && (
                                  <>
                                      <div>
                                          <label
                                              htmlFor="username"
                                              className="block text-sm font-medium text-white/90 mb-1.5"
                                          >
                                              Username
                                          </label>
                                          <input
                                              id="username"
                                              type="text"
                                              value={username}
                                              onChange={(e) =>
                                                  setUsername(e.target.value)
                                              }
                                              placeholder="Enter your username"
                                              required
                                              autoFocus
                                              autoCapitalize="none"
                                              autoCorrect="off"
                                              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-lg text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-transparent transition-all duration-200 "
                                          />
                                      </div>

                                      <div>
                                          <label
                                              htmlFor="password"
                                              className="block text-sm font-medium text-white/90 mb-1.5"
                                          >
                                              Password
                                          </label>
                                          <input
                                              id="password"
                                              type="password"
                                              value={password}
                                              onChange={(e) =>
                                                  setPassword(e.target.value)
                                              }
                                              placeholder="Enter your password"
                                              required
                                              autoCapitalize="none"
                                              autoCorrect="off"
                                              className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-lg text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-transparent transition-all duration-200 "
                                          />
                                      </div>
                                  </>
                              )}

                              {/* Step 2: 2FA Token Input */}
                              {requires2FA && (
                                  <div className="animate-fade-in space-y-4">
                                      <div className="p-4 bg-brand/10 border border-brand/20 rounded-lg">
                                          <p className="text-white/90 text-sm font-semibold mb-1">
                                              Two-Factor Authentication Required
                                          </p>
                                          <p className="text-white/60 text-xs">
                                              Logging in as{" "}
                                              <strong>{username}</strong>
                                          </p>
                                      </div>
                                      <div>
                                          <label
                                              htmlFor="twoFactorToken"
                                              className="block text-sm font-medium text-white/90 mb-1.5"
                                          >
                                              {useRecoveryCode
                                                  ? "Recovery Code"
                                                  : "Authentication Code"}
                                          </label>
                                          <input
                                              id="twoFactorToken"
                                              type="text"
                                              value={twoFactorToken}
                                              onChange={(e) => {
                                                  if (useRecoveryCode) {
                                                      // Recovery code: 8 hex characters
                                                      setTwoFactorToken(
                                                          e.target.value
                                                              .replace(
                                                                  /[^A-Fa-f0-9]/g,
                                                                  ""
                                                              )
                                                              .slice(0, 8)
                                                              .toUpperCase()
                                                      );
                                                  } else {
                                                      // TOTP: 6 digits
                                                      setTwoFactorToken(
                                                          e.target.value
                                                              .replace(/\D/g, "")
                                                              .slice(0, 6)
                                                      );
                                                  }
                                              }}
                                              placeholder={
                                                  useRecoveryCode
                                                      ? "ABCD1234"
                                                      : "000000"
                                              }
                                              maxLength={
                                                  useRecoveryCode ? 8 : 6
                                              }
                                              required
                                              autoFocus
                                              autoCapitalize="none"
                                              autoCorrect="off"
                                              className="w-full px-4 py-2.5 bg-white/5 border border-brand/30 rounded-lg text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-brand/50 focus:border-transparent transition-all duration-200  text-center text-2xl tracking-widest"
                                          />
                                          <p className="text-xs text-white/50 mt-2">
                                              {useRecoveryCode
                                                  ? "Enter your 8-character recovery code"
                                                  : "Enter the 6-digit code from your authenticator app"}
                                          </p>
                                      </div>

                                      {/* Toggle between TOTP and Recovery Code */}
                                      <div className="flex items-center justify-center">
                                          <button
                                              type="button"
                                              onClick={() => {
                                                  setUseRecoveryCode(
                                                      !useRecoveryCode
                                                  );
                                                  setTwoFactorToken("");
                                                  setError("");
                                              }}
                                              className="text-xs text-brand hover:text-brand-light transition-colors underline"
                                          >
                                              {useRecoveryCode
                                                  ? "Use authenticator app instead"
                                                  : "Use recovery code instead"}
                                          </button>
                                      </div>
                                  </div>
                              )}

                              <button
                                  type="submit"
                                  disabled={isLoading}
                                  className="w-full py-3 bg-[#fca200] text-black font-bold rounded-lg hover:bg-[#e69200] transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                  <span className="flex items-center justify-center gap-2">
                                      {isLoading ? (
                                          <>
                                              <Loader2 className="w-5 h-5 animate-spin" />
                                              Signing in...
                                          </>
                                      ) : (
                                          "Sign In"
                                      )}
                                  </span>
                              </button>

                              {requires2FA && (
                                  <button
                                      type="button"
                                      onClick={() => {
                                          setRequires2FA(false);
                                          setTwoFactorToken("");
                                          setUseRecoveryCode(false);
                                          setError("");
                                      }}
                                      className="w-full text-xs text-white/50 hover:text-white/80 transition-colors"
                                  >
                                      ← Back to login
                                  </button>
                              )}

                              <button
                                  type="button"
                                  onClick={() => {
                                      setShowCredentials(false);
                                      setError("");
                                      setUsername("");
                                      setPassword("");
                                  }}
                                  className="w-full text-xs text-white/50 hover:text-white/80 transition-colors"
                              >
                                  ← Back to main login
                              </button>
                          </form>
                      )}
                  </div>

                  {/* Footer */}
                  <p className="text-center text-white/40 text-sm mt-6">
                      © 2025 Kima. Your music, your way.
                  </p>
              </div>
          </div>
      </div>
  );
}
