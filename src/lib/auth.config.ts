// lib/auth.config.ts
import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma";
import { comparePassword } from "@/lib/auth";

// Ensure environment variables are available
const {
  NEXTAUTH_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
} = process.env;

export const authOptions: NextAuthOptions = {
  ...(process.env.DATABASE_URL ? { adapter: PrismaAdapter(prisma) } : {}),
  providers: [
    CredentialsProvider({
      id: "credentials",
      name: "Email and Password",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "your@email.com" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Email and password are required");
        }

        try {
          // Find user in database
          const user = await prisma.user.findUnique({
            where: {
              email: credentials.email.toLowerCase(),
            }
          });

          if (!user || !user.password) {
            throw new Error("Invalid email or password");
          }

          // Compare password
          const isPasswordValid = await comparePassword(
            credentials.password,
            user.password
          );

          if (!isPasswordValid) {
            throw new Error("Invalid email or password");
          }

          // Return user object (password excluded)
          const { password, ...userWithoutPassword } = user;
          return {
            ...userWithoutPassword,
            name: user.name ?? '',
            image: user.image ?? '',
            emailVerified: user.emailVerified ?? undefined,
          };
        } catch (error) {
          console.error("Authentication error:", error);
          throw new Error("Authentication failed");
        }
      },
    }),
    ...(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET ? [
      GoogleProvider({
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        authorization: {
          params: {
            prompt: "consent",
            access_type: "offline",
            response_type: "code"
          }
        }
      })
    ] : []),
  ],
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async jwt({ token, user, account }) {
      // Initial sign in
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.picture = user.image;
      }
      
      // Handle Google OAuth account linking
      if (account?.provider === "google") {
        token.accessToken = account.access_token;
      }
      
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id as string;
        session.user.email = token.email as string;
        session.user.name = token.name as string;
        session.user.image = token.picture as string;
      }
      return session;
    },
    async signIn({ user, account, profile }) {
      // Allow credentials login
      if (account?.provider === "credentials") {
        return true;
      }
      
      // Handle Google OAuth
      if (account?.provider === "google" && profile?.email) {
        try {
          // Check if user exists with this email
          const existingUser = await prisma.user.findUnique({
            where: { email: profile.email.toLowerCase() },
          });

          if (existingUser) {
            // User exists, allow sign in
            return true;
          } else {
            // New user, will be created by PrismaAdapter
            return true;
          }
        } catch (error) {
          console.error("Sign in error:", error);
          return false;
        }
      }
      
      return true;
    },
  },
  pages: {
    signIn: "/login",
    error: "/login", // Redirect to login page on error
  },
  secret: NEXTAUTH_SECRET,
  debug: process.env.NEXTAUTH_DEBUG === "true",
};